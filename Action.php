<?php
namespace TypechoPlugin\Oidc;

use Exception;
use Typecho\Common;
use Typecho\Db;
use Widget\ActionInterface;
use Widget\Base;
use Widget\Notice;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Action extends Base implements ActionInterface
{
    /**
     * 插件配置
     */
    protected $pluginConfig;

    /**
     * 提示框组件
     */
    protected $notice;

    /**
     * 初始化组件
     */
    protected function init()
    {
        parent::init();
        $this->pluginConfig = $this->options->plugin('Oidc');
        $this->notice = Notice::alloc();
    }


    // ==================== 公共接口方法 ====================

    /**
     * 动作接口 - 根据 do 参数分发请求
     * 所有通过 action 的操作都需要登录和 CSRF 保护
     */
    public function action()
    {
        // 检查用户是否登录
        if (!$this->user->hasLogin()) {
            $this->response->redirect($this->options->loginUrl);
            exit;
        }

        // CSRF 保护
        $this->security->protect();

        $do = $this->request->get('do');

        switch ($do) {
            case 'unbind':
                $this->unbind();
                break;
            default:
                $this->response->setStatus(404);
                exit;
        }
    }

    // ==================== 公共操作方法 ====================

    /**
     * 登录跳转
     */
    public function login()
    {
        if (!$this->isPluginEnabled()) {
            $this->loginError('插件已禁用，请联系管理员');
        }
        // 检查配置是否完整
        if (empty($this->pluginConfig->discoveryUrl) || empty($this->pluginConfig->clientId) || empty($this->pluginConfig->clientSecret)) {
            $this->loginError('OIDC 配置不完整，请联系管理员');
        }

        // 确保 session 已启动
        $this->startSession();

        $this->captureLoginContext();

        // 生成 state 参数
        $state = bin2hex(random_bytes(16));

        // 将 state 存储到 Session 中，有效期 5 分钟
        $_SESSION['oidc_state'] = array(
            'value' => $state,
            'expires_at' => time() + 300
        );

        // 构建授权 URL
        $redirectUri = Common::url('/oidc/callback', $this->options->index);

        // 获取授权端点
        $discoveryData = $this->getDiscoveryData();
        if ($discoveryData && isset($discoveryData['authorization_endpoint'])) {
            $authorizeUrl = $discoveryData['authorization_endpoint'];
        } else {
            $this->loginError('无法获取 OIDC 授权端点');
        }

        $authorizeUrl .= '?client_id=' . urlencode($this->pluginConfig->clientId);
        $authorizeUrl .= '&response_type=code';
        $authorizeUrl .= '&redirect_uri=' . urlencode($redirectUri);
        $authorizeUrl .= '&scope=' . urlencode($this->pluginConfig->scope);
        $authorizeUrl .= '&state=' . urlencode($state);

        if ($this->isPkceEnabled()) {
            $pkcePair = $this->generatePkcePair();
            $_SESSION['oidc_pkce'] = array(
                'verifier' => $pkcePair['verifier'],
                'expires_at' => time() + 300
            );
            $authorizeUrl .= '&code_challenge=' . urlencode($pkcePair['challenge']);
            $authorizeUrl .= '&code_challenge_method=S256';
        }

        // 重定向到 OIDC 授权页面
        $this->response->redirect($authorizeUrl);
    }

    /**
     * 回调处理
     */
    public function callback()
    {
        if (!$this->isPluginEnabled()) {
            $this->loginError('插件已禁用，请联系管理员');
        }
        // 获取 code 和 state
        $code = $this->request->get('code');
        $state = $this->request->get('state');

        if (empty($code)) {
            $error = $this->request->get('error');
            $errorDescription = $this->request->get('error_description');
            error_log("OIDC 授权失败: {$error} - {$errorDescription}");
            $this->loginError('授权失败，请重试');
        }

        // 验证 state 参数
        if (!$this->verifyState($state)) {
            $this->loginError('State 验证失败，可能存在 CSRF 攻击');
        }

        // 获取 token
        $tokenData = $this->getAccessToken($code);

        if (empty($tokenData) || empty($tokenData['access_token'])) {
            $this->loginError('获取 Access Token 失败');
        }

        if (!empty($tokenData['id_token']) && is_string($tokenData['id_token'])) {
            $_SESSION['oidc_last_id_token'] = $tokenData['id_token'];
        }

        // 使用 Access Token 获取用户信息
        $userInfo = $this->getUserInfo($tokenData['access_token']);
        if (empty($userInfo)) {
            $this->loginError('获取用户信息失败');
        }

        // 添加 issuer（从 discovery 获取）
        if (empty($userInfo['iss'])) {
            $discoveryData = $this->getDiscoveryData();
            if (!empty($discoveryData['issuer'])) {
                $userInfo['iss'] = $discoveryData['issuer'];
            }
        }

        // 处理用户登录
        $this->processUserLogin($userInfo);
    }

    /**
     * 自定义登录页
     */
    public function loginPage()
    {
        if (!$this->isPluginEnabled()) {
            $this->loginError('插件已禁用，请联系管理员');
        }

        if ($this->user->hasLogin()) {
            $this->response->redirect($this->options->adminUrl);
            exit;
        }

        if (!$this->shouldKeepNativePasswordLogin()) {
            $this->login();
            return;
        }

        $this->startSession();
        include dirname(__FILE__) . '/LoginPage.php';
        exit;
    }

    /**
     * 统一登出：Typecho 本地退出 + 跳转 IdP/账户中心退出
     */
    public function logout()
    {
        $this->startSession();

        // 优先读取用户当前绑定 provider 信息
        $issuer = null;
        if ($this->user->hasLogin()) {
            try {
                $db = Db::get();
                $prefix = $db->getPrefix();
                $binding = $db->fetchRow(
                    $db->select('iss')
                        ->from($prefix . 'oidc_bindings')
                        ->where('uid = ?', $this->user->uid)
                        ->limit(1)
                );
                if (!empty($binding['iss'])) {
                    $issuer = (string) $binding['iss'];
                }
            } catch (\Throwable $e) {
                error_log('OIDC: 获取绑定 issuer 失败 - ' . $e->getMessage());
            }
        }

        // 本地先登出
        if ($this->user->hasLogin()) {
            $this->user->logout();
        }
        @session_destroy();

        $postLogoutRedirect = Common::url('/', $this->options->index);
        $target = $this->buildUnifiedLogoutTarget($issuer, $postLogoutRedirect);
        $this->response->redirect($target);
        exit;
    }

    /**
     * 解绑 OIDC 账户
     */
    public function unbind()
    {
        if (!$this->isUserUnbindAllowed()) {
            $this->notice->set(_t('当前站点不允许解绑 OIDC 账户'), 'error');
            $this->response->redirect($this->getOidcPanelUrl());
            exit;
        }

        $bindingId = $this->request->get('binding_id');
        if (empty($bindingId)) {
            $bindingId = $this->request->post('binding_id');
        }
        $bindingId = intval($bindingId);

        if ($bindingId <= 0) {
            $this->notice->set(_t('无效的绑定ID'), 'error');
            $this->response->redirect($this->getOidcPanelUrl());
            exit;
        }

        try {
            $db = Db::get();
            $prefix = $db->getPrefix();

            // 确保只能解绑自己的账户
            $db->query(
                $db->delete($prefix . 'oidc_bindings')
                    ->where('id = ?', $bindingId)
                    ->where('uid = ?', $this->user->uid)
            );

            $this->notice->set(_t('解绑成功'), 'success');
        } catch (Exception $e) {
            error_log('OIDC 解绑错误: ' . $e->getMessage());
            $this->notice->set(_t('解绑失败，请稍后重试'), 'error');
        }

        // 重定向回管理面板
        $this->response->redirect($this->getOidcPanelUrl());
        exit;
    }

    // ==================== 私有核心业务方法 ====================

    /**
     * 处理用户登录
     *
     * @param array $userInfo 用户信息
     */
    private function processUserLogin($userInfo)
    {
        // 检查是否有 sub 字段
        if (empty($userInfo['sub'])) {
            $this->loginError('用户信息中缺少 sub 字段');
        }

        // 检查是否有 iss 字段（OIDC issuer，作为 provider 标识）
        if (empty($userInfo['iss'])) {
            $this->loginError('用户信息中缺少 iss 字段');
        }

        $sub = $userInfo['sub'];
        $iss = $userInfo['iss']; // OIDC Issuer
        $db = Db::get();
        $prefix = $db->getPrefix();

        // 查找绑定关系（使用 iss + sub 组合）
        try {
            $binding = $db->fetchRow(
                $db->select('uid')->from($prefix . 'oidc_bindings')
                    ->where('iss = ?', $iss)
                    ->where('sub = ?', $sub)
            );

            if ($binding) {
                // 找到绑定，重新生成 Session ID（防止 Session 固定攻击）
                session_regenerate_id(true);

                // 直接登录
                $this->user->simpleLogin($binding['uid'], false);

                if ($this->user->hasLogin()) {
                    $this->syncTypechoProfileByUserInfo((int) $binding['uid'], $userInfo);
                    // 登录成功，跳转到后台
                    $this->redirectAfterLogin($this->options->adminUrl);
                } else {
                    $this->loginError('登录失败，请重试');
                }
            } else {
                // 当前已登录用户点击“绑定”时，应优先进入绑定流程，避免误走自动注册分支
                if ($this->user->hasLogin()) {
                    $this->handleBinding($userInfo);
                    return;
                }

                if ($this->isAutoRegisterEnabled()) {
                    $uid = $this->autoRegisterUser($userInfo);
                    if ($uid) {
                        $this->bindUser($uid, $userInfo);
                        $this->loginByUid($uid, $userInfo);
                        return;
                    }
                }

                // 未找到绑定关系，需要先绑定
                $this->handleBinding($userInfo);
            }
        } catch (Exception $e) {
            error_log('OIDC 登录错误: ' . $e->getMessage());
            $this->loginError('登录过程中发生错误，请稍后重试');
        }
    }

    /**
     * 处理绑定流程
     *
     * @param array $userInfo 用户信息
     */
    private function handleBinding($userInfo)
    {
        // 检查用户是否已经登录
        if (!$this->user->hasLogin()) {
            // 用户未登录，提示需要先登录
            $this->loginError('请先登录 Typecho 账户，然后在 OIDC 绑定管理页面进行绑定');
        }

        try {
            $db = Db::get();
            $prefix = $db->getPrefix();

            // 检查是否已经绑定（使用 iss + sub 组合）
            $existingBinding = $db->fetchRow(
                $db->select()->from($prefix . 'oidc_bindings')
                    ->where('iss = ?', $userInfo['iss'])
                    ->where('sub = ?', $userInfo['sub'])
            );

            if ($existingBinding) {
                $this->loginError('该 OIDC 账户已被绑定到其他账户');
            }

            $this->bindUser($this->user->uid, $userInfo);

            $this->syncTypechoProfileByUserInfo((int) $this->user->uid, $userInfo);

            // 确保用户已登录
            if (!$this->user->hasLogin()) {
                $this->user->simpleLogin($this->user->uid, false);
            }

            // 添加成功提示
            $this->notice->set(_t('OIDC 账户绑定成功'), 'success');

            // 绑定成功，跳转到 OIDC 绑定管理面板
            $this->redirectAfterLogin($this->getOidcPanelUrl());

        } catch (Exception $e) {
            error_log('OIDC 绑定错误: ' . $e->getMessage());
            $this->loginError('绑定过程中发生错误，请稍后重试');
        }
    }

    /**
     * 绑定用户与 OIDC 账户
     *
     * @param int $uid
     * @param array $userInfo
     */
    private function bindUser($uid, $userInfo)
    {
        $db = Db::get();
        $prefix = $db->getPrefix();

        $db->query(
            $db->insert($prefix . 'oidc_bindings')
                ->rows(array(
                    'uid' => $uid,
                    'iss' => $userInfo['iss'],
                    'sub' => $userInfo['sub'],
                    'created_at' => time()
                ))
        );
    }

    /**
     * 自动注册用户
     *
     * @param array $userInfo
     * @return int|null
     */
    private function autoRegisterUser($userInfo)
    {
        $emailClaim = $this->getClaimName('emailClaim');
        $email = $this->getClaimValue($userInfo, $emailClaim);

        if (empty($email) || !$this->isEmailVerified($userInfo)) {
            $this->loginError('邮箱未验证或缺失，无法自动注册');
        }

        $db = Db::get();
        $prefix = $db->getPrefix();

        $existingEmail = $db->fetchRow(
            $db->select('uid')->from($prefix . 'users')
                ->where('mail = ?', $email)
        );
        if ($existingEmail) {
            $this->loginError('该邮箱已被其他账户使用，请使用密码登录后在绑定管理页面绑定 OIDC 账户');
        }

        $username = $this->normalizeUsername($userInfo['sub']);
        $username = $this->ensureUniqueUsername($username);

        $screenNameClaim = $this->getClaimName('nicknameClaim');
        $screenName = $this->getClaimValue($userInfo, $screenNameClaim);
        if (empty($screenName)) {
            $screenName = $username;
        }
        $screenName = $this->truncateValue($screenName, 32);

        $homepageClaim = $this->getClaimName('homepageClaim');
        $homepage = $this->getClaimValue($userInfo, $homepageClaim);
        $homepage = $this->truncateValue($homepage, 200);

        $password = $this->generateRandomPassword();

        $db->query(
            $db->insert($prefix . 'users')
                ->rows(array(
                    'name' => $username,
                    'password' => Common::hash($password),
                    'mail' => $email,
                    'url' => $homepage,
                    'screenName' => $screenName,
                    'created' => time(),
                    'activated' => time(),
                    'logged' => 0,
                    'group' => $this->getAutoRegisterGroup()
                ))
        );

        $createdUser = $db->fetchRow(
            $db->select('uid')->from($prefix . 'users')
                ->where('name = ?', $username)
        );
        if (empty($createdUser['uid'])) {
            $this->loginError('自动注册失败，请稍后重试');
        }

        return (int) $createdUser['uid'];
    }

    /**
     * 通过 uid 登录
     *
     * @param int $uid
     */
    private function loginByUid($uid, $userInfo = null)
    {
        session_regenerate_id(true);
        $this->user->simpleLogin($uid, false);

        if ($this->user->hasLogin()) {
            if (is_array($userInfo)) {
                $this->syncTypechoProfileByUserInfo((int) $uid, $userInfo);
            }

            $this->redirectAfterLogin($this->options->adminUrl);
        }

        $this->loginError('登录失败，请重试');
    }

    // ==================== 私有 OIDC 协议方法 ====================

    /**
     * 获取访问令牌和 ID Token
     *
     * @param string $code 授权码
     * @return array|false 包含 access_token 和 id_token 的数组或 false
     */
    private function getAccessToken($code)
    {
        $this->startSession();
        // 确定 token 端点 URL
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['token_endpoint'])) {
            error_log('OIDC: 无法获取 Token 端点');
            return false;
        }

        $redirectUri = Common::url('/oidc/callback', $this->options->index);

        // 构建请求头（RFC 6749 §2.3.1 要求对 client_id 和 client_secret 进行 form-urlencoded 编码）
        $authHeader = 'Basic ' . base64_encode(rawurlencode($this->pluginConfig->clientId) . ':' . rawurlencode($this->pluginConfig->clientSecret));

        $headers = array(
            'Authorization: ' . $authHeader,
            'Content-Type: application/x-www-form-urlencoded'
        );

        // 构建请求体
        $postData = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'scope' => $this->pluginConfig->scope
        );

        if ($this->isPkceEnabled()) {
            $pkceVerifier = $this->getPkceVerifier();
            if (empty($pkceVerifier)) {
                error_log('OIDC: PKCE 校验失败，缺少 code_verifier');
                return false;
            }
            $postData['code_verifier'] = $pkceVerifier;
        }

        // 发送请求
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $discoveryData['token_endpoint']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!empty($curlError)) {
            error_log('OIDC: 获取 Token 失败 - ' . $curlError);
        }

        if ($httpCode != 200 || empty($response)) {
            return false;
        }

        $responseData = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE || empty($responseData['access_token'])) {
            return false;
        }

        return $responseData;
    }

    /**
     * 从 UserInfo 端点获取用户信息
     *
     * @param string $accessToken Access Token
     * @param object $pluginConfig 插件配置
     * @return array|false 用户信息数组或 false
     */
    private function getUserInfo($accessToken)
    {
        // 获取 UserInfo 端点
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['userinfo_endpoint'])) {
            error_log('OIDC: 无法获取 UserInfo 端点');
            return false;
        }

        // 调用 UserInfo 端点
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $discoveryData['userinfo_endpoint']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Authorization: Bearer ' . $accessToken
        ));

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!empty($curlError)) {
            error_log('OIDC: 获取 UserInfo 失败 - ' . $curlError);
            return false;
        }

        if ($httpCode != 200 || empty($response)) {
            error_log('OIDC: UserInfo 端点返回错误: HTTP ' . $httpCode);
            return false;
        }

        $userInfo = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('OIDC: 无法解析 UserInfo 响应');
            return false;
        }

        // 验证必需字段
        if (empty($userInfo['sub'])) {
            error_log('OIDC: UserInfo 缺少 sub 字段');
            return false;
        }

        return $userInfo;
    }

    /**
     * 获取 OIDC 发现文档数据
     *
     * @param string $discoveryUrl 发现文档 URL
     * @return array|false 发现文档数据或 false
     */
    private function getDiscoveryData()
    {
        // 确保 session 已启动
        $this->startSession();

        // 检查是否有缓存
        $cacheKey = 'oidc_discovery_' . md5($this->pluginConfig->discoveryUrl);

        if (isset($_SESSION[$cacheKey])) {
            $data = $_SESSION[$cacheKey];
            if ($data && isset($data['expires_at']) && $data['expires_at'] > time()) {
                return $data['data'];
            }
        }

        // 获取发现文档
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->pluginConfig->discoveryUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($httpCode != 200 || empty($response)) {
            if (!empty($curlError)) {
                error_log('OIDC: 获取发现文档失败 - ' . $curlError);
            }
            return false;
        }

        $discoveryData = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return false;
        }

        // 缓存数据到 Session（1 小时）
        $_SESSION[$cacheKey] = array(
            'data' => $discoveryData,
            'expires_at' => time() + 3600
        );

        return $discoveryData;
    }

    /**
     * 按 issuer 获取发现文档
     *
     * @param string $issuer
     * @return array|false
     */
    private function getDiscoveryDataByIssuer($issuer)
    {
        $issuer = trim((string) $issuer);
        if ($issuer === '' || !filter_var($issuer, FILTER_VALIDATE_URL)) {
            return false;
        }

        $url = rtrim($issuer, '/') . '/.well-known/openid-configuration';
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!empty($curlError) || $httpCode !== 200 || empty($response)) {
            return false;
        }

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
            return false;
        }

        return $data;
    }

    // ==================== 私有验证和工具方法 ====================

    /**
     * 验证 State 参数
     *
     * @param string $state 接收到的 state 值
     * @return bool 验证是否通过
     */
    private function verifyState($state)
    {
        // 确保 session 已启动
        $this->startSession();

        if (empty($state)) {
            return false;
        }

        // 从 Session 中获取存储的 state
        if (empty($_SESSION['oidc_state'])) {
            return false;
        }

        $storedStateData = $_SESSION['oidc_state'];
        if (!is_array($storedStateData) || empty($storedStateData['value'])) {
            return false;
        }

        // 检查是否过期
        if (time() > $storedStateData['expires_at']) {
            unset($_SESSION['oidc_state']);
            return false;
        }

        // 比较 state 值（使用时间安全的比较方法）
        $isValid = hash_equals($storedStateData['value'], $state);

        // 验证后删除 state（一次性使用）
        unset($_SESSION['oidc_state']);

        return $isValid;
    }

    /**
     * 启动 Session
     */
    private function startSession()
    {
        if (session_status() === PHP_SESSION_NONE) {
            // 设置安全的 Session 配置
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_samesite', 'Lax');

            // 如果是 HTTPS，设置 secure 标志
            if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
                ini_set('session.cookie_secure', 1);
            }

            session_start();
        }
    }

    /**
     * 是否启用插件功能
     *
     * @return bool
     */
    private function isPluginEnabled()
    {
        return empty($this->pluginConfig->enablePlugin) || $this->pluginConfig->enablePlugin === '1';
    }

    /**
     * 是否启用自动注册
     *
     * @return bool
     */
    private function isAutoRegisterEnabled()
    {
        return !empty($this->pluginConfig->enableAutoRegister) && $this->pluginConfig->enableAutoRegister === '1';
    }

    /**
     * 是否启用账户中心接管
     *
     * @return bool
     */
    private function isAccountCenterTakeoverEnabled()
    {
        if (!$this->isPluginEnabled()) {
            return false;
        }

        if (empty($this->pluginConfig->enableAccountCenterTakeover) || $this->pluginConfig->enableAccountCenterTakeover !== '1') {
            return false;
        }

        if (empty($this->pluginConfig->disableNativeAuthPages) || $this->pluginConfig->disableNativeAuthPages !== '1') {
            return false;
        }

        if (empty($this->pluginConfig->keepNativePasswordLogin) || $this->pluginConfig->keepNativePasswordLogin !== '0') {
            return false;
        }

        if (!empty($this->pluginConfig->allowUserUnbind) && $this->pluginConfig->allowUserUnbind !== '0') {
            return false;
        }

        $accountCenterUrl = !empty($this->pluginConfig->accountCenterUrl) ? trim((string) $this->pluginConfig->accountCenterUrl) : '';
        if ($accountCenterUrl === '' || !filter_var($accountCenterUrl, FILTER_VALIDATE_URL)) {
            return false;
        }

        return true;
    }

    /**
     * 是否保留本地账号登录入口
     *
     * @return bool
     */
    private function shouldKeepNativePasswordLogin()
    {
        return empty($this->pluginConfig->keepNativePasswordLogin) || $this->pluginConfig->keepNativePasswordLogin === '1';
    }

    /**
     * 是否允许用户解绑 OIDC 账户
     *
     * @return bool
     */
    private function isUserUnbindAllowed()
    {
        return !empty($this->pluginConfig->allowUserUnbind) && $this->pluginConfig->allowUserUnbind === '1';
    }

    /**
     * 获取自动注册用户组
     *
     * @return string
     */
    private function getAutoRegisterGroup()
    {
        $allowedGroups = array('subscriber', 'contributor', 'editor');
        $group = !empty($this->pluginConfig->autoRegisterGroup) ? (string) $this->pluginConfig->autoRegisterGroup : 'subscriber';

        if (!in_array($group, $allowedGroups, true)) {
            return 'subscriber';
        }

        return $group;
    }

    /**
     * 根据 IdP 用户信息刷新 Typecho 资料
     *
     * @param int $uid
     * @param array $userInfo
     */
    private function syncTypechoProfileByUserInfo($uid, $userInfo)
    {
        if (!$this->isAccountCenterTakeoverEnabled()) {
            return;
        }

        $updates = array();

        $emailClaim = $this->getClaimName('emailClaim');
        $email = $this->getClaimValue($userInfo, $emailClaim);
        if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $updates['mail'] = $this->truncateValue($email, 200);
        }

        $screenNameClaim = $this->getClaimName('nicknameClaim');
        $screenName = $this->getClaimValue($userInfo, $screenNameClaim);
        if (!empty($screenName)) {
            $sanitizedScreenName = trim(strip_tags((string) $screenName));
            $sanitizedScreenName = preg_replace('/[\x00-\x1F\x7F]/u', '', $sanitizedScreenName);
            $sanitizedScreenName = $this->truncateValue($sanitizedScreenName, 32);
            if ($sanitizedScreenName !== '') {
                $updates['screenName'] = $sanitizedScreenName;
            }
        }

        $homepageClaim = $this->getClaimName('homepageClaim');
        $homepage = $this->getClaimValue($userInfo, $homepageClaim);
        if (!empty($homepage) && is_string($homepage)) {
            $homepage = trim($homepage);
            if (filter_var($homepage, FILTER_VALIDATE_URL)) {
                $homepageParts = parse_url($homepage);
                $scheme = isset($homepageParts['scheme']) ? strtolower((string) $homepageParts['scheme']) : '';
                if ($scheme === 'http' || $scheme === 'https') {
                    $updates['url'] = $this->truncateValue($homepage, 200);
                }
            }
        }

        if (empty($updates)) {
            return;
        }

        $db = Db::get();
        $prefix = $db->getPrefix();
        $db->query(
            $db->update($prefix . 'users')
                ->rows($updates)
                ->where('uid = ?', $uid)
        );
    }

    /**
     * 捕获登录上下文（用于 profile 页面回跳）
     */
    private function captureLoginContext()
    {
        if (!$this->request->is('sync_profile=1')) {
            unset($_SESSION['oidc_login_context']);
            return;
        }

        $returnTo = $this->sanitizeReturnTo((string) $this->request->get('return_to'));
        $_SESSION['oidc_login_context'] = array(
            'sync_profile' => 1,
            'return_to' => $returnTo,
            'expires_at' => time() + 300
        );
    }

    /**
     * 消费登录上下文
     *
     * @return array|null
     */
    private function consumeLoginContext()
    {
        if (empty($_SESSION['oidc_login_context']) || !is_array($_SESSION['oidc_login_context'])) {
            return null;
        }

        $context = $_SESSION['oidc_login_context'];
        unset($_SESSION['oidc_login_context']);

        if (empty($context['expires_at']) || (int) $context['expires_at'] < time()) {
            return null;
        }

        return $context;
    }

    /**
     * 登录后跳转
     *
     * @param string $defaultUrl
     */
    private function redirectAfterLogin($defaultUrl)
    {
        $context = $this->consumeLoginContext();
        if (
            !empty($context)
            && !empty($context['sync_profile'])
            && !empty($context['return_to'])
            && $this->sanitizeReturnTo((string) $context['return_to']) !== ''
        ) {
            $returnTo = (string) $context['return_to'];
            $separator = strpos($returnTo, '?') === false ? '?' : '&';
            $this->response->redirect($returnTo . $separator . 'oidc_synced=1');
            exit;
        }

        $this->response->redirect($defaultUrl);
        exit;
    }

    /**
     * 校验回跳 URL 安全性
     *
     * @param string $returnTo
     * @return string
     */
    private function sanitizeReturnTo($returnTo)
    {
        $returnTo = trim($returnTo);
        if ($returnTo === '') {
            return '';
        }

        if (strlen($returnTo) > 1000) {
            return '';
        }

        $parsed = parse_url($returnTo);
        if (!is_array($parsed)) {
            return '';
        }

        if (empty($parsed['scheme']) || empty($parsed['host'])) {
            return '';
        }

        $scheme = strtolower((string) $parsed['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            return '';
        }

        $adminParsed = parse_url($this->options->adminUrl);
        if (!is_array($adminParsed) || empty($adminParsed['host'])) {
            return '';
        }

        $host = strtolower((string) $parsed['host']);
        $adminHost = strtolower((string) $adminParsed['host']);
        if ($host !== $adminHost) {
            return '';
        }

        $port = isset($parsed['port']) ? (int) $parsed['port'] : ($scheme === 'https' ? 443 : 80);
        $adminScheme = isset($adminParsed['scheme']) ? strtolower((string) $adminParsed['scheme']) : $scheme;
        $adminPort = isset($adminParsed['port']) ? (int) $adminParsed['port'] : ($adminScheme === 'https' ? 443 : 80);
        if ($port !== $adminPort) {
            return '';
        }

        $adminPathPrefix = isset($adminParsed['path']) ? rtrim((string) $adminParsed['path'], '/') : '';
        $path = isset($parsed['path']) ? (string) $parsed['path'] : '';
        if ($adminPathPrefix !== '' && strpos($path, $adminPathPrefix) !== 0) {
            return '';
        }

        return $returnTo;
    }

    /**
     * 生成统一登出目标地址
     *
     * @param string|null $issuer
     * @param string $postLogoutRedirect
     * @return string
     */
    private function buildUnifiedLogoutTarget($issuer, $postLogoutRedirect)
    {
        if (!$this->isAccountCenterTakeoverEnabled()) {
            return $postLogoutRedirect;
        }

        $configured = !empty($this->pluginConfig->accountCenterLogoutUrl) ? trim((string) $this->pluginConfig->accountCenterLogoutUrl) : '';
        if ($this->isAllowedLogoutUrl($configured, true)) {
            return $configured;
        }

        $discoveryData = false;
        if (!empty($issuer)) {
            $discoveryData = $this->getDiscoveryDataByIssuer((string) $issuer);
        }

        if (!$discoveryData) {
            $discoveryData = $this->getDiscoveryData();
        }

        if (is_array($discoveryData) && !empty($discoveryData['end_session_endpoint'])) {
            $endpoint = (string) $discoveryData['end_session_endpoint'];
            if ($this->isAllowedLogoutUrl($endpoint, false)) {
                $sep = strpos($endpoint, '?') === false ? '?' : '&';
                $target = $endpoint . $sep . 'post_logout_redirect_uri=' . rawurlencode($postLogoutRedirect);
                if (!empty($_SESSION['oidc_last_id_token']) && is_string($_SESSION['oidc_last_id_token'])) {
                    $target .= '&id_token_hint=' . rawurlencode($_SESSION['oidc_last_id_token']);
                }
                return $target;
            }
        }

        return $postLogoutRedirect;
    }

    /**
     * 登出 URL 白名单校验
     *
     * @param string $url
     * @param bool $enforceSameHost 是否要求与账户中心 URL 同 host
     * @return bool
     */
    private function isAllowedLogoutUrl($url, $enforceSameHost)
    {
        $url = trim((string) $url);
        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }

        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower((string) $parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            return false;
        }

        if (!$enforceSameHost) {
            return true;
        }

        $accountCenterUrl = !empty($this->pluginConfig->accountCenterUrl) ? trim((string) $this->pluginConfig->accountCenterUrl) : '';
        if ($accountCenterUrl === '' || !filter_var($accountCenterUrl, FILTER_VALIDATE_URL)) {
            return false;
        }

        $centerParts = parse_url($accountCenterUrl);
        if (!is_array($centerParts) || empty($centerParts['host'])) {
            return false;
        }

        return strtolower((string) $parts['host']) === strtolower((string) $centerParts['host']);
    }

    /**
     * 获取 OIDC 绑定面板 URL（兼容自定义后台目录）
     *
     * @return string
     */
    private function getOidcPanelUrl()
    {
        return Common::url('extending.php?panel=Oidc%2FPanel.php', $this->options->adminUrl);
    }

    /**
     * 获取 Claim 名称
     *
     * @param string $configKey
     * @return string|null
     */
    private function getClaimName($configKey)
    {
        if (empty($this->pluginConfig->$configKey)) {
            return null;
        }

        return trim($this->pluginConfig->$configKey);
    }

    /**
     * 获取 Claim 值
     *
     * @param array $userInfo
     * @param string|null $claimName
     * @return string|null
     */
    private function getClaimValue($userInfo, $claimName)
    {
        if (empty($claimName) || empty($userInfo[$claimName])) {
            return null;
        }

        $value = $userInfo[$claimName];
        if (!is_string($value)) {
            return null;
        }

        return trim($value);
    }

    /**
     * 判断邮箱是否已验证
     *
     * @param array $userInfo
     * @return bool
     */
    private function isEmailVerified($userInfo)
    {
        if (!array_key_exists('email_verified', $userInfo)) {
            return false;
        }

        $value = $userInfo['email_verified'];
        if ($value === true || $value === 1 || $value === '1') {
            return true;
        }

        if (is_string($value) && strtolower($value) === 'true') {
            return true;
        }

        return false;
    }

    /**
     * 规范化用户名
     *
     * @param string $sub
     * @return string
     */
    private function normalizeUsername($sub)
    {
        $sanitized = preg_replace('/[^a-zA-Z0-9_]/', '_', $sub);
        $sanitized = trim($sanitized, '_');

        if (empty($sanitized)) {
            $sanitized = 'oidc_' . substr(hash('sha256', $sub), 0, 24);
        }

        if (strlen($sanitized) > 32) {
            $sanitized = 'oidc_' . substr(hash('sha256', $sub), 0, 27);
        }

        return $sanitized;
    }

    /**
     * 确保用户名唯一
     *
     * @param string $username
     * @return string
     */
    private function ensureUniqueUsername($username)
    {
        $db = Db::get();
        $prefix = $db->getPrefix();
        $base = $username;
        $attempt = 0;

        while ($attempt < 5) {
            $exists = $db->fetchRow(
                $db->select('uid')->from($prefix . 'users')
                    ->where('name = ?', $username)
            );

            if (!$exists) {
                return $username;
            }

            $suffix = substr(bin2hex(random_bytes(2)), 0, 4);
            $availableLength = 32 - strlen($suffix) - 1;
            $username = substr($base, 0, max(1, $availableLength)) . '_' . $suffix;
            $attempt++;
        }

        return 'oidc_' . substr(bin2hex(random_bytes(8)), 0, 24);
    }

    /**
     * 生成随机密码
     *
     * @return string
     */
    private function generateRandomPassword()
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * 截断字符串
     *
     * @param string|null $value
     * @param int $length
     * @return string
     */
    private function truncateValue($value, $length)
    {
        if (empty($value) || !is_string($value)) {
            return '';
        }

        if (strlen($value) <= $length) {
            return $value;
        }

        return substr($value, 0, $length);
    }

    /**
     * 是否启用 PKCE
     *
     * @return bool
     */
    private function isPkceEnabled()
    {
        return !empty($this->pluginConfig->enablePkce) && $this->pluginConfig->enablePkce === '1';
    }

    /**
     * 生成 PKCE verifier 和 challenge
     *
     * @return array
     */
    private function generatePkcePair()
    {
        $verifier = $this->base64UrlEncode(random_bytes(32));
        $challenge = $this->base64UrlEncode(hash('sha256', $verifier, true));

        return array(
            'verifier' => $verifier,
            'challenge' => $challenge
        );
    }

    /**
     * 获取 PKCE verifier
     *
     * @return string|null
     */
    private function getPkceVerifier()
    {
        if (empty($_SESSION['oidc_pkce']) || !is_array($_SESSION['oidc_pkce'])) {
            return null;
        }

        $data = $_SESSION['oidc_pkce'];
        if (empty($data['verifier']) || empty($data['expires_at']) || time() > $data['expires_at']) {
            unset($_SESSION['oidc_pkce']);
            return null;
        }

        unset($_SESSION['oidc_pkce']);

        return $data['verifier'];
    }

    /**
     * Base64URL 编码
     *
     * @param string $input
     * @return string
     */
    private function base64UrlEncode($input)
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }

    /**
     * 显示登录错误信息并退出
     *
     * @param string $message 错误信息
     */
    private function loginError($message)
    {
        // 清理敏感的 Session 数据
        $this->startSession();
        unset($_SESSION['oidc_state']);

        $errorMessage = $message;
        include dirname(__FILE__) . '/Error.php';
        exit;
    }
}

if (!class_exists('Oidc_Action', false)) {
    class_alias(__NAMESPACE__ . '\\Action', 'Oidc_Action');
}
