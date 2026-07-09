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
                // 解绑是状态变更操作，仅允许 POST 请求
                $requestMethod = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : '';
                if ($requestMethod !== 'POST') {
                    $this->response->setStatus(405);
                    exit;
                }
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

        // 生成 state 和 nonce 参数
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        // 将 state 和 nonce 存储到 Session 中，有效期 5 分钟
        $_SESSION['oidc_state'] = array(
            'value' => $state,
            'nonce' => $nonce,
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
        $authorizeUrl .= '&nonce=' . urlencode($nonce);

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
            self::logSafe("OIDC 授权失败: {$error} - {$errorDescription}");
            $this->loginError('授权失败，请重试');
        }

        // 验证 state 参数，并取出存储的 nonce
        $storedNonce = $this->verifyState($state);
        if ($storedNonce === false) {
            $this->loginError('State 验证失败，可能存在 CSRF 攻击');
        }

        // 获取 token
        $tokenData = $this->getAccessToken($code);

        if (empty($tokenData) || empty($tokenData['access_token'])) {
            $this->loginError('获取 Access Token 失败');
        }

        // 验证 ID Token（签名 + claims）
        if (empty($tokenData['id_token'])) {
            $this->loginError('Token 响应中缺少 id_token');
        }

        $idTokenClaims = $this->verifyIdToken($tokenData['id_token'], $storedNonce);
        if (!$idTokenClaims) {
            $this->loginError('ID Token 验证失败');
        }

        // 保存 id_token 用于后续登出（id_token_hint）
        $_SESSION['oidc_last_id_token'] = $tokenData['id_token'];

        // 使用 Access Token 获取用户信息（用于补充 email/nickname 等非身份标识 claims）
        $userInfo = $this->getUserInfo($tokenData['access_token']);
        if (empty($userInfo)) {
            $this->loginError('获取用户信息失败');
        }

        // 安全模型：以已验证 ID Token 的 iss/sub 作为权威身份来源，
        // UserInfo 的 sub 必须与 ID Token 一致，否则拒绝登录
        if (empty($userInfo['sub']) || !hash_equals((string) $idTokenClaims['sub'], (string) $userInfo['sub'])) {
            self::logSafe('OIDC: UserInfo sub 与 ID Token sub 不匹配');
            $this->loginError('身份验证失败，请重试');
        }

        // 用已验证的 ID Token claims 覆盖身份标识字段
        $userInfo['sub'] = $idTokenClaims['sub'];
        $userInfo['iss'] = $idTokenClaims['iss'];

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
                self::logSafe('OIDC: 获取绑定 issuer 失败 - ' . $e->getMessage());
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

        $bindingId = $this->request->post('binding_id');
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
            self::logSafe('OIDC 解绑错误: ' . $e->getMessage());
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
            self::logSafe('OIDC 登录错误: ' . $e->getMessage());
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
            self::logSafe('OIDC 绑定错误: ' . $e->getMessage());
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
            self::logSafe('OIDC: 无法获取 Token 端点');
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
                self::logSafe('OIDC: PKCE 校验失败，缺少 code_verifier');
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
            self::logSafe('OIDC: 获取 Token 失败 - ' . $curlError);
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
            self::logSafe('OIDC: 无法获取 UserInfo 端点');
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
            self::logSafe('OIDC: 获取 UserInfo 失败 - ' . $curlError);
            return false;
        }

        if ($httpCode != 200 || empty($response)) {
            self::logSafe('OIDC: UserInfo 端点返回错误: HTTP ' . $httpCode);
            return false;
        }

        $userInfo = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::logSafe('OIDC: 无法解析 UserInfo 响应');
            return false;
        }

        // 验证必需字段
        if (empty($userInfo['sub'])) {
            self::logSafe('OIDC: UserInfo 缺少 sub 字段');
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
                self::logSafe('OIDC: 获取发现文档失败 - ' . $curlError);
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
     * 验证 State 参数，返回存储的 nonce（如果有）
     *
     * @param string $state 接收到的 state 值
     * @return string|false 验证通过返回存储的 nonce 字符串（可能为空字符串），否则 false
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

        if (!$isValid) {
            return false;
        }

        // 返回存储的 nonce（可能为空，兼容旧 session）
        return isset($storedStateData['nonce']) ? $storedStateData['nonce'] : '';
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
     * Base64URL 解码
     *
     * @param string $input
     * @return string|false
     */
    private static function base64UrlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'), true);
    }

    // ==================== ID Token 验证 ====================

    /**
     * 验证 ID Token：签名 + iss/aud/exp/iat/nbf/nonce
     *
     * @param string $idToken JWT 字符串
     * @param string $expectedNonce 期望的 nonce（来自 session，可为空）
     * @return array|false 验证通过返回 claims；否则 false
     */
    private function verifyIdToken($idToken, $expectedNonce)
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            self::logSafe('OIDC: ID Token 格式无效');
            return false;
        }

        list($headerB64, $payloadB64, $signatureB64) = $parts;
        $header = json_decode(self::base64UrlDecode($headerB64), true);
        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        $signature = self::base64UrlDecode($signatureB64);

        if (!is_array($header) || !is_array($payload) || $signature === false) {
            self::logSafe('OIDC: ID Token 解析失败');
            return false;
        }

        $alg = isset($header['alg']) ? $header['alg'] : '';
        $signingInput = $headerB64 . '.' . $payloadB64;
        $discoveryData = $this->getDiscoveryData();
        if (!is_array($discoveryData)) {
            self::logSafe('OIDC: 无法获取发现文档用于验证 ID Token');
            return false;
        }

        // 拒绝 alg=none
        if (empty($alg) || $alg === 'none') {
            self::logSafe('OIDC: ID Token alg 无效');
            return false;
        }

        // 检查 alg 是否被 discovery 声明支持
        if (!empty($discoveryData['id_token_signing_alg_values_supported'])
            && is_array($discoveryData['id_token_signing_alg_values_supported'])
            && !in_array($alg, $discoveryData['id_token_signing_alg_values_supported'], true)) {
            self::logSafe('OIDC: ID Token alg 未被发现文档声明支持');
            return false;
        }

        // RSA/ES 系列需要 OpenSSL
        if (($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512'
            || $alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512')
            && !function_exists('openssl_verify')) {
            self::logSafe('OIDC: PHP OpenSSL 扩展不可用，无法验证 ID Token 签名');
            return false;
        }

        // 校验签名
        if ($alg === 'HS256') {
            $clientSecret = (string) $this->pluginConfig->clientSecret;
            if ($clientSecret === '') {
                self::logSafe('OIDC: HS256 需要 Client Secret');
                return false;
            }
            $expected = hash_hmac('sha256', $signingInput, $clientSecret, true);
            if (!hash_equals($expected, $signature)) {
                self::logSafe('OIDC: ID Token HS256 签名验证失败');
                return false;
            }
        } elseif ($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512') {
            $publicKey = $this->getJwkPublicKey(isset($header['kid']) ? $header['kid'] : null, $alg);
            if (!$publicKey) {
                self::logSafe('OIDC: 无法获取匹配的 JWK 公钥');
                return false;
            }
            $hashAlg = $alg === 'RS256' ? OPENSSL_ALGO_SHA256 : ($alg === 'RS384' ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA512);
            if (openssl_verify($signingInput, $signature, $publicKey, $hashAlg) !== 1) {
                self::logSafe('OIDC: ID Token RSA 签名验证失败');
                return false;
            }
        } elseif ($alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512') {
            $publicKey = $this->getJwkPublicKey(isset($header['kid']) ? $header['kid'] : null, $alg);
            if (!$publicKey) {
                self::logSafe('OIDC: 无法获取匹配的 JWK 公钥');
                return false;
            }
            $signatureSize = $alg === 'ES256' ? 32 : ($alg === 'ES384' ? 48 : 66);
            $derSignature = self::ecdsaJoseSignatureToDer($signature, $signatureSize);
            if ($derSignature === false) {
                self::logSafe('OIDC: ID Token ECDSA 签名格式无效');
                return false;
            }
            $hashAlg = $alg === 'ES256' ? OPENSSL_ALGO_SHA256 : ($alg === 'ES384' ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA512);
            if (openssl_verify($signingInput, $derSignature, $publicKey, $hashAlg) !== 1) {
                self::logSafe('OIDC: ID Token ECDSA 签名验证失败');
                return false;
            }
        } else {
            self::logSafe('OIDC: 不支持的 ID Token 签名算法: ' . preg_replace('/[^A-Za-z0-9]/', '', (string) $alg));
            return false;
        }

        // 校验 claims

        // iss
        $expectedIss = isset($discoveryData['issuer']) ? $discoveryData['issuer'] : '';
        if (empty($payload['iss']) || $payload['iss'] !== $expectedIss) {
            self::logSafe('OIDC: ID Token iss 不匹配');
            return false;
        }

        // aud
        $clientId = (string) $this->pluginConfig->clientId;
        $aud = isset($payload['aud']) ? $payload['aud'] : null;
        $audMatch = is_array($aud) ? in_array($clientId, $aud, true) : $aud === $clientId;
        if (!$audMatch) {
            self::logSafe('OIDC: ID Token aud 不匹配');
            return false;
        }
        // aud 为数组时必须验证 azp
        if (is_array($aud) && count($aud) > 1) {
            if (!isset($payload['azp']) || $payload['azp'] !== $clientId) {
                self::logSafe('OIDC: ID Token azp 不匹配');
                return false;
            }
        }

        // 时间校验（含 60s leeway）
        $now = time();
        $leeway = 60;
        if (empty($payload['exp']) || !is_numeric($payload['exp']) || (int) $payload['exp'] + $leeway < $now) {
            self::logSafe('OIDC: ID Token 已过期');
            return false;
        }
        if (isset($payload['iat']) && (!is_numeric($payload['iat']) || (int) $payload['iat'] - $leeway > $now)) {
            self::logSafe('OIDC: ID Token iat 在未来');
            return false;
        }
        if (isset($payload['nbf']) && (!is_numeric($payload['nbf']) || (int) $payload['nbf'] - $leeway > $now)) {
            self::logSafe('OIDC: ID Token nbf 在未来');
            return false;
        }

        // nonce（防重放）
        if (!empty($expectedNonce)) {
            if (empty($payload['nonce']) || !hash_equals((string) $expectedNonce, (string) $payload['nonce'])) {
                self::logSafe('OIDC: ID Token nonce 验证失败');
                return false;
            }
        }

        // sub（必须存在）
        if (empty($payload['sub'])) {
            self::logSafe('OIDC: ID Token 缺少 sub');
            return false;
        }

        return $payload;
    }

    /**
     * 从 jwks_uri 拉取并匹配公钥（PEM）
     *
     * @param string|null $kid Key ID
     * @param string $alg JWT 签名算法
     * @return string|false PEM 公钥或 false
     */
    private function getJwkPublicKey($kid, $alg)
    {
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['jwks_uri'])) {
            return false;
        }

        $jwks = $this->fetchJwks($discoveryData['jwks_uri'], false);
        $matched = $jwks ? self::matchJwk($jwks, $kid, $alg) : null;

        // kid 不匹配时强制刷新（IdP 可能轮换了密钥）
        if (!$matched && $kid !== null) {
            $jwks = $this->fetchJwks($discoveryData['jwks_uri'], true);
            $matched = $jwks ? self::matchJwk($jwks, $kid, $alg) : null;
        }

        if (!$matched || empty($matched['kty'])) {
            return false;
        }

        if ($matched['kty'] === 'RSA') {
            if (empty($matched['n']) || empty($matched['e'])) {
                return false;
            }
            return self::rsaJwkToPem($matched['n'], $matched['e']);
        }

        if ($matched['kty'] === 'EC') {
            if (empty($matched['crv']) || empty($matched['x']) || empty($matched['y'])) {
                return false;
            }
            return self::ecJwkToPem($matched['crv'], $matched['x'], $matched['y']);
        }

        return false;
    }

    /**
     * 拉取 JWKS（含 Session 缓存，1 小时）
     *
     * @param string $jwksUri
     * @param bool $forceRefresh 强制跳过缓存
     * @return array|false
     */
    private function fetchJwks($jwksUri, $forceRefresh)
    {
        $this->startSession();
        $cacheKey = 'oidc_jwks_' . md5($jwksUri);

        if (!$forceRefresh && isset($_SESSION[$cacheKey])) {
            $cached = $_SESSION[$cacheKey];
            if (is_array($cached) && !empty($cached['expires_at']) && $cached['expires_at'] > time()) {
                return $cached['data'];
            }
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $jwksUri);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode != 200 || empty($response)) {
            return false;
        }

        $jwks = json_decode($response, true);
        if (!is_array($jwks) || empty($jwks['keys'])) {
            return false;
        }

        // 缓存 1 小时
        $_SESSION[$cacheKey] = array(
            'data' => $jwks,
            'expires_at' => time() + 3600
        );

        return $jwks;
    }

    /**
     * 在 JWKS 中匹配 kid / alg / key use
     *
     * @param array $jwks
     * @param string|null $kid
     * @param string $alg
     * @return array|null
     */
    private static function matchJwk($jwks, $kid, $alg)
    {
        $expectedKty = self::expectedJwkKty($alg);
        foreach ($jwks['keys'] as $key) {
            if (!is_array($key) || empty($key['kty']) || $key['kty'] !== $expectedKty) {
                continue;
            }
            if ($kid !== null && (!isset($key['kid']) || $key['kid'] !== $kid)) {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            if (isset($key['key_ops']) && is_array($key['key_ops']) && !in_array('verify', $key['key_ops'], true)) {
                continue;
            }
            if (isset($key['alg']) && $key['alg'] !== $alg) {
                continue;
            }
            if (!self::jwkCurveMatchesAlg($key, $alg)) {
                continue;
            }
            return $key;
        }
        return null;
    }

    /**
     * 根据 JWT alg 推导 JWK kty
     *
     * @param string $alg
     * @return string|null
     */
    private static function expectedJwkKty($alg)
    {
        if ($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512') {
            return 'RSA';
        }
        if ($alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512') {
            return 'EC';
        }
        return null;
    }

    /**
     * 校验 EC JWK 曲线是否匹配 JWT alg
     *
     * @param array $key
     * @param string $alg
     * @return bool
     */
    private static function jwkCurveMatchesAlg($key, $alg)
    {
        if (empty($key['crv'])) {
            return true;
        }
        $curves = array(
            'ES256' => 'P-256',
            'ES384' => 'P-384',
            'ES512' => 'P-521'
        );
        return empty($curves[$alg]) || $key['crv'] === $curves[$alg];
    }

    /**
     * 将 RSA JWK (n, e) 转为 PEM 公钥
     *
     * @param string $n Base64URL 编码的模数
     * @param string $e Base64URL 编码的指数
     * @return string|false
     */
    private static function rsaJwkToPem($n, $e)
    {
        $modulus = self::base64UrlDecode($n);
        $exponent = self::base64UrlDecode($e);
        if ($modulus === false || $exponent === false || $modulus === '' || $exponent === '') {
            return false;
        }

        // 高位为 1 时需要前置 0x00 以表示正数
        $modulus = (ord($modulus[0]) > 0x7f ? "\x00" : '') . $modulus;
        $exponent = (ord($exponent[0]) > 0x7f ? "\x00" : '') . $exponent;

        $modulusEncoded = self::derEncodeInteger($modulus);
        $exponentEncoded = self::derEncodeInteger($exponent);
        $rsaPublicKey = self::derEncodeSequence($modulusEncoded . $exponentEncoded);

        // SubjectPublicKeyInfo
        $rsaOid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitString = "\x03" . self::derEncodeLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $spki = self::derEncodeSequence($rsaOid . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * 将 EC JWK (crv, x, y) 转为 PEM 公钥
     *
     * @param string $crv 曲线名称
     * @param string $x Base64URL 编码的 X 坐标
     * @param string $y Base64URL 编码的 Y 坐标
     * @return string|false
     */
    private static function ecJwkToPem($crv, $x, $y)
    {
        $x = self::base64UrlDecode($x);
        $y = self::base64UrlDecode($y);
        if ($x === false || $y === false || $x === '' || $y === '') {
            return false;
        }

        $curveOids = array(
            'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
            'P-521' => "\x06\x05\x2b\x81\x04\x00\x23"
        );
        if (empty($curveOids[$crv])) {
            return false;
        }

        $ecPublicKeyOid = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $algorithm = self::derEncodeSequence($ecPublicKeyOid . $curveOids[$crv]);
        $publicKey = "\x04" . $x . $y;
        $bitString = "\x03" . self::derEncodeLength(strlen($publicKey) + 1) . "\x00" . $publicKey;
        $spki = self::derEncodeSequence($algorithm . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * 将 JOSE ECDSA 签名（r || s）转为 OpenSSL 需要的 DER 格式
     *
     * @param string $signature
     * @param int $size 单个整数长度
     * @return string|false
     */
    private static function ecdsaJoseSignatureToDer($signature, $size)
    {
        if (strlen($signature) !== $size * 2) {
            return false;
        }
        $r = substr($signature, 0, $size);
        $s = substr($signature, $size);
        return self::derEncodeSequence(self::derEncodeUnsignedInteger($r) . self::derEncodeUnsignedInteger($s));
    }

    /**
     * DER 编码无符号整数（去掉前导零，高位为 1 时补 0x00）
     *
     * @param string $value
     * @return string
     */
    private static function derEncodeUnsignedInteger($value)
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if (ord($value[0]) > 0x7f) {
            $value = "\x00" . $value;
        }
        return self::derEncodeInteger($value);
    }

    /**
     * DER 编码 Length
     *
     * @param int $len
     * @return string
     */
    private static function derEncodeLength($len)
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * DER 编码 Integer
     *
     * @param string $value
     * @return string
     */
    private static function derEncodeInteger($value)
    {
        return "\x02" . self::derEncodeLength(strlen($value)) . $value;
    }

    /**
     * DER 编码 Sequence
     *
     * @param string $value
     * @return string
     */
    private static function derEncodeSequence($value)
    {
        return "\x30" . self::derEncodeLength(strlen($value)) . $value;
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

    /**
     * 安全写日志（过滤换行/控制符，防止日志注入）
     *
     * 攻击者可通过构造含 \n 的 OIDC 回调参数（如 error_description），
     * 在服务器日志中伪造额外的日志行。本方法将所有控制字符
     * (0x00-0x1F, 0x7F) 替换为空格。
     *
     * @param string $message
     */
    private static function logSafe($message)
    {
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $message);
        if ($sanitized === null) {
            $sanitized = preg_replace('/[\x00-\x1F\x7F]/', ' ', (string) $message);
        }
        error_log($sanitized);
    }
}

if (!class_exists('Oidc_Action', false)) {
    class_alias(__NAMESPACE__ . '\\Action', 'Oidc_Action');
}
