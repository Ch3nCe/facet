# -*- coding: utf-8 -*-
"""
facet — 全量指纹库与动态规则路由

设计目标:
1. 首发命中: 主页 HTML + 响应头 → 秒级判定目标技术栈
2. 按指纹路由: 不同技术栈启用不同的 JS 分析规则集, 减少噪音、提升命中率
3. 可扩展: 新增指纹只需往 FP_RULES 追加条目, 不影响既有逻辑
4. 外部化: 支持 --fingerprint-db 运行时加载自定义指纹库, 无需改源码

指纹分类:
- 前端框架 (React/Vue/Angular/Svelte/Solid/Next/Nuxt/Remix)
- 后端框架/CMS (Django/Spring/Express/Laravel/WordPress/Drupal)
- API 架构风格 (REST/GraphQL/gRPC/tRPC/Swagger/OpenAPI)
- 中间件/WAF (Cloudflare/CloudFront/Akamai/Nginx/Apache)
- 云服务 (AWS/Azure/GCP/阿里云/Vercel/Netlify)
- 构建工具 (Webpack/Vite/Rollup/Parcel/esbuild)
- 认证方案 (JWT/OAuth2/SAML/SSO/CAS)
- 敏感特征 (Admin panel/Debug mode/DevTools/Stack trace暴露)

规则表(实际存在两张 —— 历史上曾有 JS_API_RULES / JS_BUILD_RULES / HEADER_RULES /
BODY_RULES / ERROR_RULES / CLOUD_RULES 等分散表, 已并入下面两张, 勿再按旧名引用):
- `FP_RULES`          指纹识别规则 (头部 / body / JS 特征 → 指纹名), 见 §1
- `ROUTE_RULES`       指纹 → 启用的"通用开关名"清单 (如 `'vue': {'VUE_ROUTER'}`), 见 §2
- `ROUTE_EXTRA_PATTERNS` 按**开关名**登记的栈专属提取正则, 见 §2.2
                      (由 `get_extra_route_patterns(enabled)` 取用)
"""

import json
import re
from urllib.parse import urlparse

from ..core.log import dbg

# 1. 指纹规则库 (可扩展: 新增指纹只需追加条目)

FP_RULES = [
    # ---- 前端框架 ----
    ('React',              {'body': [r'<div\s+id=["\']root["\']', r'react-root', r'__REACT_LOADABLE__',
                                    r'\.lazy\s*\(', r'react\.production\.min\.js', r'react-dom'],
                            'headers': [], 'js': [r'from\s*["\']react["\']', r'React\s*\.\s*createElement',
                                                   r'useState\s*\(', r'useEffect\s*\(']}),
    ('Vue',                {'body': [r'vue\.js', r'vue\.min\.js', r'__VUE__', r'data-v-', r'vue-router'],
                            'headers': [], 'js': [r'Vue\s*\.\s*createApp', r'new\s+Vue\s*\(',
                                                   r'from\s*["\']vue["\']', r'\.vue\s*\?']}),
    ('Vue3',               {'body': [r'vue\.global\.js', r'vue\.runtime\.esm-bundler'],
                            'headers': [], 'js': [r'createApp\s*\(', r'Composition API',
                                                   r'defineProps\s*\(', r'pinia']}),
    ('Angular',            {'body': [r'ng-app', r'ng-controller', r'angular\.js', r'angular\.min\.js'],
                            'headers': [], 'js': [r'@angular/core', r'AngularModule',
                                                   r'\$http\s*\.', r'\$resource\s*\(']}),
    ('Svelte',             {'body': [r'svelte-[0-9a-f]{6}\.js', r'__SVELTE__'],
                            'headers': [], 'js': [r'\.svelte', r'svelte/internal',
                                                   r'create_ssr_component']}),
    # SvelteKit 单列 —— 它的构建产物目录(/_app/immutable/)与数据端点
    # (__data.json)与 Svelte 组件库完全不同, 需要各自的隐藏路径层。
    ('SvelteKit',          {'body': [r'__sveltekit_', r'/_app/immutable/', r'data-sveltekit-'],
                            'headers': [], 'js': [r'__sveltekit_', r'sveltekit']}),
    ('SolidJS',            {'body': [],
                            'headers': [], 'js': [r'solid-js', r'createSignal',
                                                   r'createEffect', r'from\s*["\']solid-js["\']']}),
    # 补 `id="__next"`(根容器)与 `__NEXT_DATA__`(JS 全局) ——
    ('Next.js',            {'body': [r'__NEXT_DATA__', r'/_next/static', r'/_next/image',
                                     r'id=["\']__next["\']', r'__next_f'],
                            'headers': [],
                            # js 侧补 `__NEXT_DATA__` / `__next_f` —— 这两个
                            #   全局变量为 Next.js 产物独有, 比 useRouter 更具专有性。
                            'js': [r'next/router', r'useRouter\s*\(', r'getServerSideProps',
                                   r'getStaticProps', r'__NEXT_DATA__', r'__next_f']}),
    # 补 `id="__nuxt"`(根容器); JS 侧补 `__NUXT__` 与 `/_nuxt/`
    ('Nuxt',               {'body': [r'window\.__NUXT__', r'/_nuxt/',
                                     r'id=["\']__nuxt["\']', r'__NUXT__'],
                            'headers': [],
                            # js 侧补 `__NUXT__` / `/_nuxt/`
                            'js': [r'useFetch\s*\(', r'\$fetch\s*\(', r'NuxtLink',
                                   r'defineNuxtComponent', r'__NUXT__', r'/_nuxt/']}),
    ('Remix',              {'body': [r'window\.__remixContext', r'/@remix-run'],
                            'headers': [], 'js': [r'remix-run', r'useLoaderData',
                                                   r'useActionData', r'Form\s+method']}),
    ('Gatsby',             {'body': [r'___gatsby', r'/page-data/'],
                            'headers': [], 'js': [r'gatsby', r'graphql\s*\`']}),
    # 裸 `island` 太通用(常见于文案), 收紧为 Astro 专有标记。
    ('Astro',              {'body': [r'astro-island', r'data-astro-'],
                            'headers': [], 'js': [r'astro', r'data-astro-cid']}),
    # `body` 信号必须**具体且克制**: ① 裸 `ember` 会命中 "member"/"remember"/"november"
    #   —— 实测 mpassport.huazhu.com 因 `member-server` 被误判为 Ember;
    #   ② 信号条数不能多 —— 命中率 = 命中/条数, 条数过多会把单条命中稀释到阈值(0.3)以下。
    #   故只保留 3 个 Ember 专有标记(单条命中即 1/3 = 0.33 ≥ 阈值)。
    ('Ember',              {'body': [r'data-ember-', r'ember-view', r'ember-application'],
                            'headers': [], 'js': [r'ember\.', r'Ember\.', r'EmberObject']}),

    # ---- 后端框架 ----
    ('Django',             {'body': [r'django', r'csrfmiddlewaretoken', r'static/admin/'],
                            'headers': [r'Server:\s*WSGIServer', r'X-Frame-Options:\s*SAMEORIGIN'],
                            'js': [r'/admin/', r'django']}),
    ('Flask',              {'body': [],
                            'headers': [r'Server:\s*Werkzeug', r'X-Powered-By:\s*Flask'],
                            'js': []}),
    ('Spring',             {'body': [r'Whitelabel Error Page', r'Spring Boot',
                                     r'actuator/health', r'/actuator'],
                            'headers': [r'X-Application-Context'],
                            'js': [r'/actuator', r'spring']}),
    # `X-Application-Context` 是 Spring Boot **独有**响应头(普通 Spring
    #   Framework 不产生它), 此前却只挂在 `Spring` 规则下 —— 导致一个标准 Spring Boot
    #   站点(仅有该头 + Whitelabel 页)只能被识别成泛化的 "Spring", 拿不到 Boot 专属
    #   的 actuator/springdoc 路由开关。
    ('Spring-Boot',        {'body': [r'/actuator', r'/swagger-ui', r'springdoc',
                                     r'Whitelabel Error Page'],
                            'headers': [r'X-Application-Context'],
                            'js': [r'actuator', r'swagger', r'springdoc']}),
    # `Express` 框架的本体判据是 `X-Powered-By: Express` 响应头 / `express.js` /
    #   `app.use(` 这类 JS 标记。**裸词 `Express` 必须去掉** —— 普通页面里的
    #   "Express delivery" / "American Express" 会误报(实测负样本触发)。
    ('Express',            {'body': [r'Powered by Express'],
                            'headers': [r'X-Powered-By:\s*Express'],
                            'js': [r'express\.js', r'app\.use\s*\(']}),
    # 去掉 body 判据里的 `csrf-token` —— 它是 Rails / Django / Laravel /
    #   Spring-Security **共享**的 CSRF 标记(实测真实 Rails 页面因此被误判为 Laravel,
    #   并连带反推出 PHP)。改用 Laravel 独有信号: `laravel_session` cookie 名 / 框架名。
    ('Laravel',            {'body': [r'laravel_session', r'Laravel'],
                            'headers': [], 'js': [r'laravel', r'axios\.defaults\.xsrfCookieName']}),
    # 去掉裸词 `rails` —— 它只是 "Ruby on Rails" 的缩写, 会命中 "trails" /
    #   "corrails" 等, 且 Rails 已有强标记 `Ruby on Rails` / `authenticity_token` /
    #   `csrf-token` / `turbo`, 去掉裸词不损召回。
    ('Rails',              {'body': [r'authenticity_token', r'csrf-token',
                                     r'Ruby on Rails'],
                            'headers': [], 'js': [r'rails', r'turbo']}),
    ('ASP.NET',            {'body': [r'__VIEWSTATE', r'ASP.NET', r'WebForms'],
                            'headers': [r'X-AspNet-Version', r'X-AspNetMvc-Version'],
                            'js': [r'__doPostBack']}),
    ('PHP',                {'body': [r'\.php', r'index\.php', r'PHPSESSID'],
                            'headers': [r'X-Powered-By:\s*PHP'],
                            'js': []}),
    ('WordPress',          {'body': [r'wp-content', r'wp-includes', r'wp-json',
                                     r'wordpress', r'wp-admin'],
                            'headers': [], 'js': [r'wp-api', r'/wp-json/wp/v2/']}),
    ('Drupal',             {'body': [r'drupal', r'Drupal.settings'],
                            'headers': [], 'js': [r'drupal', r'jQuery\.drupal']}),

    # ---- API 架构 ----
    ('REST',               {'body': [], 'headers': [],
                            'js': [r'/api/', r'/v\d+/', r'axios\.', r'fetch\s*\(', r'\.get\s*\(']}),
    # 补 `graphql` / `introspection` / `__schema` ——
    #   GraphQL 服务端对未授权 introspection 查询会回 `{"errors":[{"message":
    #   "...GraphQL introspection disabled"}]}`, 响应体本身不含 `/graphql` 字样,
    #   旧规则因此对"已知是 GraphQL 端点"的场景零命中。
    ('GraphQL',            {'body': [r'/graphql', r'graphiql', r'/api/graphql',
                                     r'graphql', r'introspection', r'__schema'],
                            'headers': [], 'js': [r'graphql', r'gql\s*\`',
                                                   r'ApolloClient', r'urql', r'relay']}),
    ('gRPC-Web',           {'body': [r'grpc-web', r'\.proto'],
                            'headers': [r'Content-Type:\s*application/grpc-web'],
                            'js': [r'grpc\.web', r'grpcweb', r'\.proto']}),
    ('tRPC',               {'body': [],
                            'headers': [], 'js': [r'trpc', r'trpc\.client',
                                                   r'createTRPCProxyClient', r'\.query\s*\(']}),
    ('Swagger',            {'body': [r'swagger-ui', r'/swagger-ui', r'/api-docs',
                                     r'/v2/api-docs', r'/v3/api-docs'],
                            'headers': [], 'js': [r'swagger', r'openapi']}),
    ('OpenAPI',            {'body': [r'openapi', r'/openapi\.json', r'/api-docs'],
                            'headers': [], 'js': [r'openapi', r'swagger']}),

    # ---- 中间件/WAF ----
    ('Nginx',              {'body': [],
                            'headers': [r'Server:\s*nginx', r'X-Accel-Redirect'],
                            'js': []}),
    ('Apache',             {'body': [r'Apache/2\.4', r'Apache/2\.2'],
                            'headers': [r'Server:\s*Apache/(?:2|1)\.', r'X-Powered-By:\s*Apache'],
                            'js': []}),
    ('Cloudflare',         {'body': [],
                            'headers': [r'CF-Ray', r'CF-Cache-Status', r'Server:\s*cloudflare'],
                            'js': []}),
    ('CloudFront',         {'body': [],
                            'headers': [r'X-Cache:\s*.*cloudfront', r'Via:\s*.*CloudFront'],
                            'js': []}),
    ('Akamai',             {'body': [],
                            'headers': [r'X-Akamai-Edge', r'X-Cache-Key', r'X-True-Cache-Key'],
                            'js': []}),
    # WAF 检测应依赖 **WAF 专有信号**(响应头 `X-WAF-Event`/`X-Security-Mode` 或
    #   阻断页短语 `Access Denied`)。**裸词 `blocked` / `captcha` 必须去掉** ——
    #   普通登录页的 "account blocked" 锁定提示、任意带验证码的页面都会误报
    #   (实测两类负样本均触发 WAF)。`Forbidden` 保留(与 `Access Denied` 同属
    #   访问控制阻断语境, 且单条 "Forbidden" 在阈值下不触发, 仅作佐证)。
    ('WAF',                {'body': [r'Access Denied', r'Forbidden'],
                            'headers': [r'X-WAF-Event', r'X-Security-Mode'],
                            'js': []}),

    # ---- 云服务 ----
    ('AWS',                {'body': [],
                            'headers': [r'x-amz-', r'X-Amz-Cf-', r'Server:\s*AmazonS3'],
                            'js': [r'aws-sdk', r'@aws-sdk', r'amazon']}),
    ('AWS-API-Gateway',    {'body': [],
                            'headers': [r'x-amzn-requestid', r'x-amzn-trace-id'],
                            'js': []}),
    ('Azure',              {'body': [],
                            'headers': [r'x-ms-request-id', r'x-azure-ref'],
                            'js': [r'@azure', r'azure']}),
    ('GCP',                {'body': [],
                            'headers': [r'x-cloud-trace-context', r'Server:\s*Google'],
                            'js': [r'@google-cloud', r'googleapis']}),
    # 原此处有一条 '阿里云' 规则, 与下方(第 284 行附近)的 '阿里云' **完全重复**
    #   且是后者的子集 —— 已删除, 消除指纹库重名(同一指纹只应有一条规则)。
    ('Vercel',             {'body': [],
                            'headers': [r'x-vercel-id', r'Server:\s*Vercel'],
                            'js': []}),
    ('Netlify',            {'body': [],
                            'headers': [r'x-nf-request-id', r'Server:\s*Netlify'],
                            'js': []}),

    # ---- 构建工具 ----
    ('Webpack',            {'body': [r'webpack'], 'headers': [],
                            'js': [r'webpackChunkName', r'__webpack_require__',
                                   r'webpackJsonp', r'\.chunk\.\w+\.js']}),
    ('Vite',               {'body': [r'vite', r'/vite/'], 'headers': [],
                            # 补两个 Vite 高度专有的构建标记 ——
                            #   `import.meta.hot` 是 Vite HMR 独有写法(webpack 用 module.hot),
                            #   `__vite__mapDeps` 是 Vite 产物的固定辅助函数。
                            #   原有 3 条里 `vite/dist` 只在 dev 依赖路径出现, 生产构建常只命中 1 条。
                            'js': [r'vite/dist', r'__vite__', r'\.vite/',
                                   r'import\.meta\.hot', r'__vite__mapDeps']}),
    ('Rollup',             {'body': [], 'headers': [],
                            'js': [r'rollup', r'\.esm\.js']}),
    ('esbuild',            {'body': [], 'headers': [],
                            'js': [r'__esbuild_register__', r'esbuild']}),
    ('Parcel',             {'body': [], 'headers': [],
                            'js': [r'parcelRequire', r'\.parcel/']}),

    # ---- 认证方案 ----
    ('JWT',                {'body': [], 'headers': [r'Authorization:\s*Bearer'],
                            'js': [r'jwt', r'jsonwebtoken', r'\.verify\s*\(',
                                   r'localStorage\.getItem\s*\(["\']token["\']',
                                   r'sessionStorage\.getItem\s*\(["\']token["\']']}),
    ('OAuth2',             {'body': [r'/oauth/', r'/auth/', r'/login/oauth'],
                            'headers': [], 'js': [r'oauth', r'authorize\?',
                                                   r'redirect_uri', r'access_token']}),
    ('SSO',                {'body': [r'/sso/', r'/cas/', r'/saml/'],
                            'headers': [r'X-Sso-Provider'], 'js': [r'sso', r'saml']}),
    ('Keycloak',           {'body': [r'keycloak', r'/auth/realms/'],
                            'headers': [], 'js': [r'keycloak', r'Keycloak']}),

    # ---- 敏感特征 (不是技术栈, 是风险信号) ----
    ('Admin-Panel',        {'body': [r'/admin', r'/manage', r'/dashboard', r'/console',
                                     r'/backend', r'/system'],
                            'headers': [], 'js': [r'/admin/', r'/manage/']}),
    ('Debug-Mode',         {'body': [r'Debug mode', r'debug=True', r'DEBUG = True',
                                     r'development', r'dev mode'],
                            'headers': [r'X-Debug-Mode'], 'js': [r'__DEBUG__', r'debug']}),
    ('DevTools-Exposed',   {'body': [r'react-devtools', r'redux-devtools', r'vue-devtools'],
                            'headers': [], 'js': [r'__REDUX_DEVTOOLS_EXTENSION__',
                                                   r'__VUE_DEVTOOLS_GLOBAL_HOOK__']}),
    ('Stack-Trace-Exposed',{'body': [r'Traceback', r'File ".*", line ', r'at .* \(.*\.js:\d+:\d+\)'],
                            'headers': [], 'js': []}),
    # CORS 误配: 只有 **通配 Origin + 同时允许凭据** 才是真误配(浏览器会拒, 但说明服务端配置错误)。
    #   旧实现的两个信号都太弱, 实测在真实站点上产生误报:
    #     · `Access-Control-Allow-Origin: *` 对公开接口是**正常**配置;
    #     · `withCredentials = false` 更是**浏览器默认值**, 与"误配"无关。
    ('CORS-Misconfig',     {'body': [],
                            'headers': [r'(?=[\s\S]*Access-Control-Allow-Credentials:\s*true)'
                                        r'(?=[\s\S]*Access-Control-Allow-Origin:\s*\*)'],
                            'js': []}),
    # ---- 国内前端框架/组件库 ----
    ('Taro',               {'body': [r'taro', r'@tarojs', r'taro\.js', r'taro-runtime'],
                            'headers': [], 'js': [r'@tarojs/taro', r'Taro\.', r'createApp\s*\(.*taro',
                                                   r'@tarojs/components', r'taroComponents']}),
    ('uni-app',            {'body': [r'uni-app', r'uniapp', r'__uniapp__', r'uni-view', r'uni-page'],
                            'headers': [], 'js': [r'uni\.', r'uni-app', r'__uniConfig',
                                                   r'uni\.request', r'uni\.navigateTo']}),
    ('Ant-Design-Pro',     {'body': [r'ant-design-pro', r'antd-pro', r'@ant-design/pro'],
                            'headers': [], 'js': [r'@ant-design/pro', r'antd-pro', r'ProLayout',
                                                   r'ProTable', r'ProForm']}),
    ('Vant',               {'body': [r'vant', r'vant-ui', r'van-', r'van-cell', r'van-button'],
                            'headers': [], 'js': [r'vant', r'Vant', r'from\s+["\']vant["\']',
                                                   r'Lazyload\s*\(\s*\{.*vant']}),
    # 收紧: 去掉 `el-`/`el-button`/`el-table` 等**弱信号**(通用 CSS 类前缀, 实测导致
    #   Element-Plus/Element-UI 在同一站点双双误报) —— 只认包名/全局名。
    ('Element-Plus',      {'body': [r'element-plus'],
                            'headers': [], 'js': [r'element-plus', r'ElementPlus',
                                                   r'from\s+["\']element-plus["\']']}),
    ('Arco-Design',        {'body': [r'arco-design', r'arco', r'arco-vue', r'arco-react'],
                            'headers': [], 'js': [r'@arco-design', r'ArcoDesign', r'ArcoVue',
                                                   r'ArcoReact']}),
    ('TDesign',            {'body': [r'tdesign', r'tdesign-vue', r'tdesign-react'],
                            'headers': [], 'js': [r'tdesign', r'TDesign', r'from\s+["\']tdesign["\']']}),
    # ---- 国内后端框架 ----
    # 注意: JS 规则**不得**含 `r'/api/'` —— 它是任何带 API 路径的 JS 都会命中的**过宽**模式,
    #   曾导致 Nuxt/Vue(Node) 站点被误判为 ThinkPHP(PHP) 并触发其专属探测(实测误报)。
    #   只保留 ThinkPHP 特有的 `thinkphp` / `.php?` 特征。
    ('ThinkPHP',           {'body': [r'thinkphp', r'ThinkPHP', r'\.php\?s=', r'/index\.php/'],
                            'headers': [r'X-Powered-By:\s*ThinkPHP'],
                            'js': [r'thinkphp', r'\.php\?']}),
    # 补 Nacos 控制台 API 路径 `/nacos/v1/` —— 它出现在页面/JS 中即为
    #   决定性证据, 而旧的 `nacos` 单词规则在"页面只提一次 nacos"时比例不达标。
    ('Spring-Cloud-Alibaba',{'body': [r'spring-cloud-alibaba', r'nacos', r'sentinel',
                                      r'seata', r'/nacos/v1/', r'nacos-config'],
                            'headers': [r'X-Nacos-', r'X-Sentinel-'],
                            'js': [r'spring-cloud', r'alibaba', r'nacos/v1',
                                   r'nacos-client', r'NacosConfig']}),
    ('Dubbo',              {'body': [],
                            'headers': [r'X-Dubbo-', r'X-Dubbo-Service'],
                            'js': [r'dubbo', r'@dubbo', r'DubboService', r'DubboConsumer']}),
    ('Beego',              {'body': [r'beego', r'Beego'],
                            'headers': [], 'js': [r'beego', r'@beego', r'BeegoApp']}),
    ('JFinal',             {'body': [r'jfinal', r'JFinal'],
                            'headers': [], 'js': [r'jfinal', r'JFinal', r'Controller\s*\{']}),
    # ---- 国内云服务 ----
    ('阿里云',              {'body': [r'aliyun', r'aliyuncs\.com', r'oss-cn-'],
                            'headers': [r'X-Aliyun-', r'Server:\s*Aliyun', r'x-oss-request-id',
                                        r'X-Alicdn-', r'X-Cache:\s*.*ALICDN'],
                            'js': [r'@alicloud', r'aliyun', r'aliyuncs']}),
    ('腾讯云',              {'body': [r'tencent', r'qcloud\.com'],
                            'headers': [r'X-Tencent-', r'X-COS-', r'Server:\s*Tencent',
                                        r'x-cos-request-id', r'X-Request-Id:\s*[a-f0-9]{32}',
                                        r'X-Cache-From-Cdn'],
                            'js': [r'@cloudbase', r'tencentcloud', r'cos\.js', r'tencent']}),
    ('华为云',              {'body': [r'huaweicloud', r'huawei\.com'],
                            'headers': [r'X-HW-', r'X-HUAWEI-', r'Server:\s*Huawei',
                                        r'X-HW-Request-Id'],
                            'js': [r'huaweicloud', r'@huaweicloud']}),
    ('百度智能云',          {'body': [r'baidu\.bce', r'baidubce'],
                            'headers': [r'X-Bce-', r'X-Baidu-', r'Server:\s*Baidu', r'Server:\s*BWS',
                                        r'x-bce-request-id'],
                            'js': [r'baidu', r'@baidu', r'bce', r'baidubce']}),
    ('金山云',              {'body': [r'ksyun', r'kingsoft'],
                            'headers': [r'X-KS-', r'Server:\s*Kingsoft', r'X-KS3-Request-Id'],
                            'js': [r'ksyun', r'kingsoft']}),
    ('UCloud',              {'body': [r'ucloud', r'ufile\.ucloud\.cn'],
                            'headers': [r'X-UCloud-', r'X-UC-'],
                            'js': [r'ucloud']}),
    ('七牛云',              {'body': [r'qiniu', r'qnm'],
                            'headers': [r'X-Qiniu-', r'X-Qnm-', r'X-Log-', r'X-Reqid'],
                            'js': [r'qiniu', r'qnm']}),
    ('又拍云',              {'body': [r'upyun', r'upyun\.com'],
                            'headers': [r'X-Upyun-', r'X-Via-\s*.*upyun', r'Server:\s*Upyun'],
                            'js': [r'upyun']}),
    ('天翼云',              {'body': [r'ctyun', r'chinatelecom'],
                            'headers': [r'X-Ctyun-', r'X-CT-', r'Server:\s*CTYun'],
                            'js': [r'ctyun']}),
    ('移动云',              {'body': [r'cmcc', r'ecloud\.10086\.cn'],
                            'headers': [r'X-CMCC-', r'X-Mobile-Cloud-'],
                            'js': [r'cmcc', r'mobile-cloud']}),
    ('京东云',              {'body': [r'jdcloud', r'jcloud'],
                            'headers': [r'X-JD-', r'X-JDCloud-'],
                            'js': [r'jdcloud']}),
    ('火山引擎',            {'body': [r'volcengine', r'verce\.app', r'bytedance'],
                            'headers': [r'X-Volc-', r'X-Ve-', r'Server:\s*Volc'],
                            'js': [r'volcengine', r'bytedance']}),
    ('网易云',              {'body': [r'netease', r'163yun'],
                            'headers': [r'X-NetEase-', r'X-NEC-'],
                            'js': [r'netease', r'163yun']}),
    ('青云科技',            {'body': [r'qingcloud', r'qcloud\.com'],
                            'headers': [r'X-QingCloud-', r'X-QC-'],
                            'js': [r'qingcloud']}),
    ('新浪云',              {'body': [r'sina\.appengine', r'sae\.sinajs'],
                            'headers': [r'X-SAE-', r'X-Sina-'],
                            'js': [r'sina']}),
    ('灵雀云',              {'body': [r'alauda'],
                            'headers': [r'X-Alauda-'],
                            'js': [r'alauda']}),
    ('时速云',              {'body': [r'tenxcloud'],
                            'headers': [r'X-Tenx-'],
                            'js': [r'tenxcloud']}),
    ('博云',                {'body': [r'bocloud'],
                            'headers': [r'X-BoCloud-'],
                            'js': [r'bocloud']}),
    ('浪潮云',              {'body': [r'inspur', r'inspurcloud'],
                            'headers': [r'X-Inspur-', r'X-IC-'],
                            'js': [r'inspur']}),
    ('用友云',              {'body': [r'yonyou'],
                            'headers': [r'X-Yonyou-'],
                            'js': [r'yonyou']}),
    ('金蝶云',              {'body': [r'kingdee'],
                            'headers': [r'X-Kingdee-'],
                            'js': [r'kingdee']}),
    # ---- 国内低代码/CMS ----
    ('JeecgBoot',          {'body': [r'jeecg', r'JeecgBoot', r'jeecg-boot', r'/jeecg/'],
                            'headers': [], 'js': [r'jeecg', r'JeecgBoot', r'/api/', r'/sys/']}),
    ('RuoYi',              {'body': [r'ruoyi', R'RuoYi', r'/ruoyi/', r'/system/'],
                            'headers': [], 'js': [r'ruoyi', r'RuoYi', r'/system/', r'/api/']}),
    ('Discuz!',            {'body': [r'discuz', r'Discuz!', r'forum\.php', r'discuz_uid',
                                     r'comsenz', r'UC_KEY'],
                            'headers': [], 'js': [r'discuz', r'Discuz', r'forum', r'/api/']}),
    ('Typecho',            {'body': [r'typecho', r'Typecho', r'usr/themes', r'index\.php/'],
                            'headers': [], 'js': [r'typecho', r'Typecho']}),
    # ---- 国外增长型前端框架 ----
    ('Qwik',               {'body': [r'qwik', r'builder\.io', r'qwik-city'],
                            'headers': [], 'js': [r'@builder\.io/qwik', r'qwik', r'useQwik',
                                                   r'qwik\s*=\s*true']}),
    ('Preact',             {'body': [r'preact', r'preact\.js'],
                            'headers': [], 'js': [r'preact', r'Preact', r'from\s+["\']preact["\']',
                                                   r'h\s*\(', r'preact/compat']}),
    ('Alpine.js',          {'body': [r'alpine', r'x-data', r'x-init', r'x-show'],
                            'headers': [], 'js': [r'alpinejs', r'Alpine', r'x-data', r'x-show',
                                                   r'Alpine\.data']}),
    ('htmx',               {'body': [r'htmx', r'hx-get', r'hx-post', r'hx-trigger'],
                            'headers': [], 'js': [r'htmx', r'htmx\.org', r'hx-get', r'hx-post',
                                                   r'htmx\.ajax']}),
    # ---- 国外增长型后端框架 ----
    ('FastAPI',            {'body': [],
                            'headers': [r'Server:\s*uvicorn', r'X-Process-Time'],
                            'js': [r'fastapi', r'FastAPI', r'/docs', r'/openapi\.json']}),
    ('Gin',                {'body': [],
                            'headers': [r'Server:\s*Gin', r'X-Gin-'],
                            'js': [r'gin-gonic', r'github\.com/gin-gonic']}),
    ('Echo',               {'body': [],
                            'headers': [r'Server:\s*Echo', r'X-Echo-'],
                            'js': [r'echo', r'labstack/echo', r'echo\.Context']}),
    ('Fiber',              {'body': [],
                            'headers': [r'Server:\s*Fiber', r'X-Fiber-'],
                            'js': [r'fiber', r'gofiber/fiber', r'fiber\.Context']}),
    ('NestJS',             {'body': [r'nestjs', r'@nestjs'],
                            'headers': [], 'js': [r'@nestjs', r'NestJS', r'@Controller',
                                                   r'@Module', r'@Injectable']}),
    ('Hono',               {'body': [],
                            'headers': [], 'js': [r'from\s*["\']hono["\']',
                                                   r'new\s+Hono']}),
    ('Elysia',             {'body': [r'elysia', r'Elysia'],
                            'headers': [], 'js': [r'elysia', r'Elysia', r'from\s*["\']elysia["\']',
                                                   r'new\s+Elysia']}),
    # ---- 数据库/BAAS ----
    ('Firebase',           {'body': [r'firebase', r'firebase-app', r'firebase-auth'],
                            'headers': [], 'js': [r'firebase', r'Firebase', r'firebase/app',
                                                   r'firebase/auth', r'firebase/firestore']}),
    ('Supabase',           {'body': [r'supabase', r'Supabase'],
                            'headers': [], 'js': [r'@supabase', r'supabase', r'createClient',
                                                   r'SupabaseClient']}),
    # ---- 国外云服务 ----
    # 去掉 `X-Request-ID` —— 它是**通用**请求追踪头(Express/Koa/FastAPI/
    #   Nginx 等普遍会带), 非 DigitalOcean 独有; 保留则任意带该头的站点都误报 DigitalOcean。
    ('DigitalOcean',       {'body': [],
                            'headers': [r'X-Do-', r'Server:\s*DigitalOcean'],
                            'js': []}),
    ('Fly.io',             {'body': [],
                            'headers': [r'Fly-Request-Id', r'Server:\s*Fly', r'Fly-Region'],
                            'js': []}),
    ('Render',             {'body': [],
                            'headers': [r'Render-Service-Name', r'X-Render-Origin-Server'],
                            'js': []}),
    # ---- 安全/WAF ----
    ('ModSecurity',        {'body': [r'403 Forbidden', r'Not Acceptable',
                                     r'ModSecurity', r'Access Denied'],
                            'headers': [r'Server:\s*ModSecurity', r'X-ModSecurity'],
                            'js': []}),
    # 去裸词 `Blocked` —— "Account Blocked" 等普通锁定提示会误报。保留
    #   `AWS WAF` 短语 + CloudFront 响应头(`X-AMZ-CF-`/`X-Cache: ...cloudfront`)。
    ('AWS-WAF',            {'body': [r'Forbidden', r'AWS WAF'],
                            'headers': [r'X-AMZ-CF-', r'X-Cache:\s*.*cloudfront'],
                            'js': []}),
    ('F5',                 {'body': [r'F5', r'Big-IP', r'The requested URL was rejected'],
                            'headers': [r'Server:\s*BIG-IP', r'X-WA-Info', r'X-Cnection'],
                            'js': []}),

    # 扩充 : 中间件 / 应用服务器
    ('Tomcat',             {'body': [r'Apache Tomcat', r'<title>Apache Tomcat'],
                            'headers': [r'Server:\s*Apache-Coyote/', r'Server:\s*Apache Tomcat'],
                            'js': []}),
    ('IIS',                {'body': [r'Microsoft-IIS', r'iisstart\.htm'],
                            'headers': [r'Server:\s*Microsoft-IIS/', r'X-Powered-By:\s*ASP\.NET'],
                            'js': []}),
    ('OpenResty',          {'body': [r'openresty'],
                            'headers': [r'Server:\s*openresty'],
                            'js': []}),
    ('Caddy',              {'body': [],
                            'headers': [r'Server:\s*Caddy(?:/|$|\s)'],
                            'js': []}),
    ('Jetty',              {'body': [r'Powered by Jetty'],
                            'headers': [r'Server:\s*Jetty'],
                            'js': []}),
    ('Undertow',           {'body': [r'Undertow'],
                            'headers': [r'Server:\s*undertow'],
                            'js': []}),
    ('Kestrel',            {'body': [],
                            'headers': [r'Server:\s*Kestrel'],
                            'js': []}),
    ('Gunicorn',           {'body': [],
                            'headers': [r'Server:\s*gunicorn'],
                            'js': []}),
    ('uWSGI',              {'body': [],
                            'headers': [r'Server:\s*uWSGI'],
                            'js': []}),
    ('LiteSpeed',          {'body': [r'LiteSpeed', r'litespeed'],
                            'headers': [r'Server:\s*LiteSpeed'],
                            'js': []}),
    ('Traefik',            {'body': [r'Traefik'],
                            'headers': [r'Server:\s*Traefik'],
                            'js': []}),
    ('Envoy',              {'body': [],
                            'headers': [r'Server:\s*envoy', r'X-Envoy-'],
                            'js': []}),
    ('Varnish',            {'body': [],
                            'headers': [r'X-Varnish:', r'Via:\s*[^\n]*varnish'],
                            'js': []}),
    ('GlassFish',          {'body': [r'GlassFish'],
                            'headers': [r'Server:\s*GlassFish'],
                            'js': []}),
    ('WebLogic',           {'body': [r'WebLogic', r'Error 404--Not Found'],
                            'headers': [r'Server:\s*WebLogic'],
                            'js': []}),
    ('JBoss',              {'body': [r'JBoss', r'JBWEB'],
                            'headers': [r'Server:\s*JBoss', r'X-Powered-By:\s*JBoss'],
                            'js': []}),
    ('WildFly',            {'body': [r'WildFly'],
                            'headers': [r'Server:\s*WildFly'],
                            'js': []}),

    # 扩充 : 后端框架
    ('Koa',                {'body': [],
                            'headers': [r'X-Powered-By:\s*koa'],
                            'js': [r'require\(["\']koa["\']\)', r'from\s+["\']koa["\']',
                                   r'new\s+Koa\s*\(', r'ctx\.(?:body|request|response)']}),
    ('Symfony',            {'body': [r'symfony', r'_sf2_attributes', r'X-Debug-Token'],
                            'headers': [r'X-Debug-Token', r'Set-Cookie:\s*sf_redirect'],
                            'js': []}),
    ('Yii',                {'body': [r'Yii Framework', r'yii\\.js'],
                            'headers': [r'X-Powered-By:\s*Yii', r'Set-Cookie:\s*YII_CSRF_TOKEN'],
                            'js': []}),
    ('CodeIgniter',        {'body': [r'CodeIgniter', r'ci_session'],
                            'headers': [r'Set-Cookie:\s*ci_session'],
                            'js': []}),
    ('CakePHP',            {'body': [r'cakephp', r'cakeSession'],
                            'headers': [r'Set-Cookie:\s*CAKEPHP', r'X-Powered-By:\s*CakePHP'],
                            'js': []}),
    ('Micronaut',          {'body': [],
                            'headers': [r'X-Powered-By:\s*Micronaut'],
                            'js': []}),
    ('Quarkus',            {'body': [],
                            'headers': [r'X-Powered-By:\s*Quarkus'],
                            'js': []}),
    ('Solon',              {'body': [],
                            'headers': [r'Server:\s*Solon', r'X-Powered-By:\s*Solon'],
                            'js': []}),

    # 扩充 : CMS / 建站系统
    ('Joomla',             {'body': [r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla',
                                     r'/media/jui/', r'/components/com_', r'joomla!'],
                            'headers': [r'Set-Cookie:\s*[0-9a-f]{32}=', r'X-Content-Encoded-By:\s*Joomla'],
                            'js': [r'Joomla\.', r'joomla\.js']}),
    ('DedeCMS',            {'body': [r'DedeCMS', r'dedecms', r'/templets/default/', r'Powered by DedeCMS'],
                            'headers': [],
                            'js': []}),
    ('PHPCMS',             {'body': [r'PHPCMS', r'phpcms', r'/statics/css/phpcms'],
                            'headers': [],
                            'js': []}),
    ('EmpireCMS',          {'body': [r'EmpireCMS', r'帝国CMS', r'/e/data/', r'Powered by EmpireCMS'],
                            'headers': [],
                            'js': []}),
    ('Z-Blog',             {'body': [r'Z-Blog', r'zb_users', r'zb_system'],
                            'headers': [],
                            'js': []}),
    ('Ecshop',             {'body': [r'ECSHOP', r'ecshop', r'/themes/default/images/'],
                            'headers': [r'Set-Cookie:\s*ECS\[', r'Set-Cookie:\s*ECS_ID'],
                            'js': []}),
    ('Shopify',            {'body': [r'cdn\.shopify\.com', r'shopify\.com/s/files',
                                     r'Shopify\.theme'],
                            'headers': [r'X-ShopId', r'X-Shopify-Stage', r'Server:\s*nginx[^\n]*shopify'],
                            'js': [r'Shopify\.', r'window\.Shopify']}),
    ('Magento',            {'body': [r'Magento', r'mage/cookies', r'/static/version\d+/',
                                     r'Magento_Ui'],
                            'headers': [r'Set-Cookie:\s*frontend=', r'X-Magento-'],
                            'js': [r'Magento_', r'mage/']}),
    ('PrestaShop',         {'body': [r'PrestaShop', r'/themes/classic/', r'prestashop'],
                            'headers': [r'Set-Cookie:\s*PrestaShop-'],
                            'js': []}),
    ('OpenCart',           {'body': [r'OpenCart', r'catalog/view/theme', r'index\.php\?route='],
                            'headers': [r'Set-Cookie:\s*OCSESSID'],
                            'js': []}),
    ('WooCommerce',        {'body': [r'woocommerce', r'wc-ajax', r'wp-content/plugins/woocommerce'],
                            'headers': [],
                            'js': [r'wc_add_to_cart_params', r'woocommerce_params']}),
    ('Ghost',              {'body': [r'ghost-url', r'content="Ghost ', r'/assets/built/'],
                            'headers': [r'X-Powered-By:\s*Express[^\n]*Ghost'],
                            'js': [r'ghost\.org', r'GhostAdmin']}),
    ('Strapi',             {'body': [r'strapi'],
                            'headers': [r'X-Powered-By:\s*Strapi'],
                            'js': [r'strapi', r'@strapi/']}),
    ('Directus',           {'body': [r'directus'],
                            'headers': [r'X-Powered-By:\s*Directus'],
                            'js': [r'directus', r'@directus/']}),

    # 扩充 : 前端 UI 库
    ('Bootstrap',          {'body': [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js',
                                     r'class="[^"]*\bcontainer-fluid\b'],
                            'headers': [],
                            'js': [r'\$\.fn\.modal', r'Bootstrap']}),
    ('Element-UI',         {'body': [r'element-ui', r'elementui'],
                            'headers': [],
                            'js': [r'ElementUI', r'element-ui/lib']}),
    ('Layui',              {'body': [r'layui\.js', r'layui\.css', r'layui-btn', r'class="layui-'],
                            'headers': [],
                            'js': [r'layui\.use\s*\(', r'layui\.config\s*\(']}),
    ('uView',              {'body': [r'u-view', r'uview', r'u-button', r'u-cell'],
                            'headers': [],
                            'js': [r'uView', r'uview-ui']}),
    ('MUI',                {'body': [r'@mui/', r'MuiButton-root', r'MuiTypography-root'],
                            'headers': [],
                            'js': [r'@mui/material', r'@material-ui/core']}),
    ('Vuetify',            {'body': [r'vuetify', r'v-application', r'class="v-'],
                            'headers': [],
                            'js': [r'Vuetify', r'createVuetify']}),
    ('Quasar',             {'body': [r'quasar', r'q-page', r'class="q-'],
                            'headers': [],
                            'js': [r'Quasar', r'quasar/']}),
    ('Naive-UI',           {'body': [r'naive-ui'],
                            'headers': [],
                            'js': [r'naive-ui', r'NButton']}),

    # 扩充 : 认证 / 会话
    ('Shiro',              {'body': [r'shiro', r'/doLogin', r'rememberMe'],
                            'headers': [r'Set-Cookie:\s*rememberMe=deleteMe'],
                            'js': []}),
    ('Sa-Token',           {'body': [r'sa-token', r'satoken'],
                            'headers': [r'Set-Cookie:\s*SATOKEN'],
                            'js': []}),
    # 误报修复: 旧 headers 规则是 `Set-Cookie: JSESSIONID` —— 但 JSESSIONID
    #   只是 Java Servlet 容器的**通用**会话 cookie, Tomcat / JBoss / WebLogic / 任意
    #   servlet 应用都会设它, 与 Spring Security 毫无关系。实测一个"只有 JSESSIONID 的
    #   普通登录页"被误判成 Spring-Security。改为 Spring Security 自己注入的 CSRF
    #   cookie `XSRF-TOKEN`(该 cookie 是它的默认行为, 其它容器不产生)。
    ('Spring-Security',    {'body': [r'spring-security', r'/login\?error', r'Spring Security'],
                            'headers': [r'Set-Cookie:\s*XSRF-TOKEN'],
                            'js': [r'spring-security', r'csrfToken']}),
    ('Auth0',              {'body': [r'cdn\.auth0\.com', r'auth0-js', r'auth0-spa-js'],
                            'headers': [],
                            'js': [r'auth0', r'Auth0Client']}),
    ('Okta',               {'body': [r'okta\.com', r'okta-sign-in'],
                            'headers': [],
                            'js': [r'@okta/okta', r'OktaSignIn']}),

    # 扩充 : WAF / 云防护 (国内优先)
    ('Imperva',            {'body': [r'Incapsula', r'_Incapsula_Resource', r'incap_ses'],
                            'headers': [r'X-Iinfo:', r'Server:\s*Imperva', r'Set-Cookie:\s*incap_ses'],
                            'js': [r'_Incapsula_Resource']}),
    ('Sucuri',             {'body': [r'Sucuri', r'sucuri\.net', r'Access Denied - Sucuri'],
                            'headers': [r'X-Sucuri-Id:', r'Server:\s*Sucuri', r'X-Sucuri-Block'],
                            'js': []}),
    ('安全狗',              {'body': [r'Safe3WAF', r'safedog', r'安全狗'],
                            'headers': [r'Server:\s*Safe3WAF', r'X-Powered-By:\s*Safe3', r'Set-Cookie:\s*SDE_'],
                            'js': []}),
    ('长亭',                {'body': [r'Chaitin', r'长亭', r'雷池'],
                            'headers': [r'Server:\s*Chaitin'],
                            'js': []}),
    ('阿里云盾',             {'body': [r'errors\.aliyun\.com', r'aliyun\.com/error', r'云盾'],
                            'headers': [r'Server:\s*Aliyun', r'X-Server-Id:\s*aliyun'],
                            'js': []}),
    ('腾讯云WAF',           {'body': [r'腾讯云', r'waf\.tencent'],
                            'headers': [r'Server:\s*Tencent-Cloud-WAF'],
                            'js': []}),
    ('百度云加速',           {'body': [r'yunjiasu', r'百度云加速'],
                            'headers': [r'Server:\s*yunjiasu', r'X-Server:\s*YJS'],
                            'js': []}),
    ('360网站卫士',          {'body': [r'wangzhan\.360\.cn', r'360wzb', r'网站卫士'],
                            'headers': [r'X-Powered-By-360WZB', r'Server:\s*360wzws'],
                            'js': []}),
    ('创宇盾',              {'body': [r'knownsec', r'创宇盾', r'365cyd'],
                            'headers': [r'Server:\s*Knownsec'],
                            'js': []}),
    ('D盾',                {'body': [r'D_Safe', r'D盾'],
                            'headers': [r'Server:\s*D_Safe'],
                            'js': []}),
    ('Wallarm',            {'body': [r'wallarm', r'nwaf'],
                            'headers': [r'Server:\s*nginx-wallarm', r'X-Wallarm-'],
                            'js': []}),
]

# 1.1 Wappalyzer 式分类
# 每条指纹归属一个 Wappalyzer 式大类, 用于在报告里按
# 「前端框架 / 后端框架 / 开发语言 / 组件与库 / 中间件与服务器 / 云与CDN /
# 安全与WAF / 风险信号」分组展示, 与 Wappalyzer 浏览器插件的技术栈视图对齐。
# 设计取舍:
#   · 分类是**独立映射表**, 不污染 FP_RULES 的判定数据 —— 新增指纹只需在
#     FP_CATEGORY 补一行, 判定逻辑与分类解耦。
#   · FP_RULES 里没有 'cat' 字段的指纹(例如外部 --fingerprint-db 注入的)
#     一律归入 '其他'。
#   · `开发语言` 类除直接命中的语言指纹(PHP)外, 还按 FP_LANG 由后端框架/CMS
#     反推(Spring→Java、Django→Python …), 还原 Wappalyzer「由框架反推语言」的行为。

FP_CATEGORY = {
    # ---- 前端框架 ----
    'React': '前端框架', 'Vue': '前端框架', 'Vue3': '前端框架', 'Angular': '前端框架',
    'Svelte': '前端框架', 'SvelteKit': '前端框架', 'SolidJS': '前端框架',
    'Next.js': '前端框架', 'Nuxt': '前端框架', 'Remix': '前端框架', 'Gatsby': '前端框架',
    'Astro': '前端框架', 'Ember': '前端框架', 'Qwik': '前端框架', 'Preact': '前端框架',
    'Alpine.js': '前端框架', 'htmx': '前端框架',
    # ---- 后端框架 / CMS ----
    'Django': '后端框架', 'Flask': '后端框架', 'Spring': '后端框架', 'Spring-Boot': '后端框架',
    'Express': '后端框架', 'Laravel': '后端框架', 'Rails': '后端框架', 'ASP.NET': '后端框架',
    'WordPress': '后端框架', 'Drupal': '后端框架', 'Koa': '后端框架', 'Symfony': '后端框架',
    'Yii': '后端框架', 'CodeIgniter': '后端框架', 'CakePHP': '后端框架', 'Micronaut': '后端框架',
    'Quarkus': '后端框架', 'Solon': '后端框架', 'NestJS': '后端框架', 'Hono': '后端框架',
    'Elysia': '后端框架', 'FastAPI': '后端框架', 'Gin': '后端框架', 'Echo': '后端框架',
    'Fiber': '后端框架', 'Beego': '后端框架', 'JFinal': '后端框架', 'ThinkPHP': '后端框架',
    'Spring-Cloud-Alibaba': '后端框架', 'Dubbo': '后端框架', 'JeecgBoot': '后端框架',
    'RuoYi': '后端框架', 'Discuz!': '后端框架', 'Typecho': '后端框架', 'Joomla': '后端框架',
    'DedeCMS': '后端框架', 'PHPCMS': '后端框架', 'EmpireCMS': '后端框架', 'Z-Blog': '后端框架',
    'Ecshop': '后端框架', 'Shopify': '后端框架', 'Magento': '后端框架', 'PrestaShop': '后端框架',
    'OpenCart': '后端框架', 'WooCommerce': '后端框架', 'Ghost': '后端框架', 'Strapi': '后端框架',
    'Directus': '后端框架', 'PHP': '开发语言',
    # ---- 组件与库 (JS 库 / UI 库 / 构建工具 / 认证 / API 架构 / BAAS) ----
    'Taro': '组件与库', 'uni-app': '组件与库', 'Ant-Design-Pro': '组件与库', 'Vant': '组件与库',
    'Element-Plus': '组件与库', 'Arco-Design': '组件与库', 'TDesign': '组件与库',
    'Bootstrap': '组件与库', 'Element-UI': '组件与库', 'Layui': '组件与库', 'uView': '组件与库',
    'MUI': '组件与库', 'Vuetify': '组件与库', 'Quasar': '组件与库', 'Naive-UI': '组件与库',
    'Webpack': '组件与库', 'Vite': '组件与库', 'Rollup': '组件与库', 'esbuild': '组件与库',
    'Parcel': '组件与库', 'JWT': '组件与库', 'OAuth2': '组件与库', 'SSO': '组件与库',
    'Keycloak': '组件与库', 'Shiro': '组件与库', 'Sa-Token': '组件与库', 'Spring-Security': '组件与库',
    'Auth0': '组件与库', 'Okta': '组件与库', 'REST': '组件与库', 'GraphQL': '组件与库',
    'gRPC-Web': '组件与库', 'tRPC': '组件与库', 'Swagger': '组件与库', 'OpenAPI': '组件与库',
    'Firebase': '组件与库', 'Supabase': '组件与库',
    # ---- 中间件与服务器 ----
    'Nginx': '中间件与服务器', 'Apache': '中间件与服务器', 'Tomcat': '中间件与服务器',
    'IIS': '中间件与服务器', 'OpenResty': '中间件与服务器', 'Caddy': '中间件与服务器',
    'Jetty': '中间件与服务器', 'Undertow': '中间件与服务器', 'Kestrel': '中间件与服务器',
    'Gunicorn': '中间件与服务器', 'uWSGI': '中间件与服务器', 'LiteSpeed': '中间件与服务器',
    'Traefik': '中间件与服务器', 'Envoy': '中间件与服务器', 'Varnish': '中间件与服务器',
    'GlassFish': '中间件与服务器', 'WebLogic': '中间件与服务器', 'JBoss': '中间件与服务器',
    'WildFly': '中间件与服务器',
    # ---- 云与CDN ----
    'Cloudflare': '云与CDN', 'CloudFront': '云与CDN', 'Akamai': '云与CDN', 'AWS': '云与CDN',
    'AWS-API-Gateway': '云与CDN', 'Azure': '云与CDN', 'GCP': '云与CDN', '阿里云': '云与CDN',
    'Vercel': '云与CDN', 'Netlify': '云与CDN', '腾讯云': '云与CDN', '华为云': '云与CDN',
    '百度智能云': '云与CDN', '金山云': '云与CDN', 'UCloud': '云与CDN', '七牛云': '云与CDN',
    '又拍云': '云与CDN', '天翼云': '云与CDN', '移动云': '云与CDN', '京东云': '云与CDN',
    '火山引擎': '云与CDN', '网易云': '云与CDN', '青云科技': '云与CDN', '新浪云': '云与CDN',
    '灵雀云': '云与CDN', '时速云': '云与CDN', '博云': '云与CDN', '浪潮云': '云与CDN',
    '用友云': '云与CDN', '金蝶云': '云与CDN', 'DigitalOcean': '云与CDN', 'Fly.io': '云与CDN',
    'Render': '云与CDN',
    # ---- 安全与WAF ----
    'WAF': '安全与WAF', 'ModSecurity': '安全与WAF', 'AWS-WAF': '安全与WAF', 'F5': '安全与WAF',
    'Imperva': '安全与WAF', 'Sucuri': '安全与WAF', '安全狗': '安全与WAF', '长亭': '安全与WAF',
    '阿里云盾': '安全与WAF', '腾讯云WAF': '安全与WAF', '百度云加速': '安全与WAF',
    '360网站卫士': '安全与WAF', '创宇盾': '安全与WAF', 'D盾': '安全与WAF', 'Wallarm': '安全与WAF',
    # ---- 风险信号 (不是技术栈, 是暴露面风险) ----
    'Admin-Panel': '风险信号', 'Debug-Mode': '风险信号', 'DevTools-Exposed': '风险信号',
    'Stack-Trace-Exposed': '风险信号', 'CORS-Misconfig': '风险信号',
}

# 由后端框架/CMS 指纹反推开发语言 (Wappalyzer「框架→语言」行为)
# 键为本库能直接判定的框架名, 值为其实现语言; 仅当该框架被命中时才反推。
FP_LANG = {
    'Spring': 'Java', 'Spring-Boot': 'Java', 'Spring-Cloud-Alibaba': 'Java',
    'JFinal': 'Java', 'Quarkus': 'Java', 'Micronaut': 'Java', 'Solon': 'Java',
    'Django': 'Python', 'Flask': 'Python', 'FastAPI': 'Python',
    'Rails': 'Ruby',
    'Laravel': 'PHP', 'ThinkPHP': 'PHP', 'Symfony': 'PHP', 'Yii': 'PHP',
    'CodeIgniter': 'PHP', 'CakePHP': 'PHP', 'WordPress': 'PHP', 'Drupal': 'PHP',
    'Gin': 'Go', 'Echo': 'Go', 'Fiber': 'Go', 'Beego': 'Go',
    'Express': 'JavaScript', 'Koa': 'JavaScript', 'NestJS': 'JavaScript',
    'Elysia': 'JavaScript', 'Hono': 'JavaScript',
    'ASP.NET': 'C#/.NET',
}

# Wappalyzer 式分类的固定展示顺序
FP_CAT_ORDER = ['前端框架', '后端框架', '开发语言', '组件与库',
                '中间件与服务器', '云与CDN', '安全与WAF', '风险信号', '其他']

# 指纹库扩容 —— 合并外部补充指纹(独立文件, 便于维护/审阅; 同名以主库为准)。
try:
    from .fingerprint_extra import EXTRA_FP_CATEGORY, EXTRA_FP_LANG, EXTRA_FP_RULES
    _have = {n for n, _ in FP_RULES}
    FP_RULES.extend([(n, r) for (n, r) in EXTRA_FP_RULES if n not in _have])
    for _k, _v in EXTRA_FP_CATEGORY.items():
        FP_CATEGORY.setdefault(_k, _v)
    for _k, _v in EXTRA_FP_LANG.items():
        FP_LANG.setdefault(_k, _v)
    for _c in ('数据库', '分析/营销'):
        if _c not in FP_CAT_ORDER:
            FP_CAT_ORDER.insert(len(FP_CAT_ORDER) - 1, _c)   # 插在 '其他' 之前
except Exception as e:
    # 扩容库合并失败静默 = **约百条指纹无声消失**且无任何日志 —— 能力宣称必须等于
    #   真实执行(全库审计 M21)。
    dbg(f'fingerprint_extra 合并失败(扩展指纹不可用): {e}')


def _uniq_patterns(pats):
    """按**小写等价**去重一组正则模式(保留首个) —— 单一真源。

    `_score_rules` / `fingerprint_from_js` 均以 `re.I` 匹配, 故 `'redis'` 与 `'Redis'`
    是**等价模式**, 同一次出现会被**计两次** → 虚高 conf(单条证据被渲染成 80%,
    违背 `_conf_cap` "证据量少→置信度低"的本意; 实测 38 个内置指纹存在此类重复对,
    外部 `--fingerprint-db` 亦可能引入)。
    """
    seen, out = set(), []
    for p in (pats or []):
        lp = p.lower()
        if lp in seen:
            continue
        seen.add(lp)
        out.append(p)
    return out


def _normalize_rule_patterns(rules_list):
    """内置规则表归一化: 去大小写等价重复(让 FP_RULES 数据本身干净、可审计)。"""
    for _name, _rules in rules_list:
        for _k in ('body', 'headers', 'url', 'js'):
            _pats = _rules.get(_k)
            if _pats:
                _u = _uniq_patterns(_pats)
                if len(_u) != len(_pats):
                    _rules[_k] = _u
    return rules_list


_normalize_rule_patterns(FP_RULES)


def categorize_fingerprints(hits, confidence):
    """把命中指纹按 Wappalyzer 式大类分组

    Args:
        hits: fingerprint_target 返回的命中名列表
        confidence: name -> 置信度(0~1)
    Returns:
        OrderedDict: 大类 -> [(name, conf), ...] (类内按置信度降序)。
        `开发语言` 类会并入由框架反推的语言(FP_LANG), 去重。
        空类被丢弃, 但保留 FP_CAT_ORDER 的展示顺序。
    """
    grouped = {c: [] for c in FP_CAT_ORDER}
    for name in hits:
        cat = FP_CATEGORY.get(name, '其他')
        grouped.setdefault(cat, []).append((name, confidence.get(name, 0)))
    # 由框架反推开发语言
    langs = {}
    for name in hits:
        lg = FP_LANG.get(name)
        if lg:
            langs[lg] = max(langs.get(lg, 0), confidence.get(name, 0))
    for lg, conf in langs.items():
        if not any(n == lg for n, _ in grouped['开发语言']):
            grouped['开发语言'].append((lg, round(conf, 2)))
    # 类内按置信度降序
    for c in grouped:
        grouped[c].sort(key=lambda x: x[1], reverse=True)
    return {c: grouped[c] for c in FP_CAT_ORDER if grouped[c]}

# 2. 按指纹路由的规则集 (分析策略)

# 各技术栈对应的 JS 分析正则权重 / 规则启用表
# 格式: {指纹名: {启用规则名: 优先级权重(0=禁用, 1=默认, 2=优先)}}
# ⚠️ 权重只对**存在消费点**的开关有意义。消费点有两类:
#   ① `js_extract.py` 里 `if 'X' in enabled:` 的分支(RE_API / RE_WRITE / RE_ROUTE / SENSITIVE …);
#   ② `ROUTE_EXTRA_PATTERNS` 里同名的指纹专属提取正则。
#   本轮全量核对 127 条 ROUTE_RULES × 50 个开关: 全部有消费点, 仅
#   `RE_TEMPLATE_URL` 例外 —— 它的行为**已无条件实现在** `_extract_write_text_v45()`
#   第 7 步(模板字符串 URL), 且 `_DEFAULT` 里权重为 1(基线常开), 因此该开关
#   实际上**不可调**(给 2 或 0 都不改变行为)。保留是为了与同族基线开关
#   (RE_API / RE_WRITE)保持一致的书写形态, 但**不要指望调它能生效**。
ROUTE_RULES = {
    # React 系
    'React':        {'RE_API': 2, 'RE_WRITE': 2, 'RE_TEMPLATE_URL': 2,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Next.js':      {'RE_API': 2, 'RE_WRITE': 2, 'RE_TEMPLATE_URL': 2,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 2, 'RE_WS': 1, 'RE_SSE': 1,
                     'SSR_EXTRA': 1},  # Next.js 优先 SSR payload 解析
    'Vue':          {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'VUE_ROUTER': 2},
    'Vue3':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'VUE_ROUTER': 2, 'PINIA': 1},
    'Angular':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 1, 'RE_SSE': 1,
                     'ANGULAR_RESOURCE': 2},
    'Svelte':       {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Nuxt':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 2, 'RE_WS': 1, 'RE_SSE': 1,
                     'NUXT_FETCH': 2, 'SSR_EXTRA': 1},
    'Remix':        {'RE_API': 2, 'RE_WRITE': 2, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'REMIX_LOADER': 2},
    'Gatsby':       {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'GRAPHQL': 2},

    # API 架构
    'GraphQL':      {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'GRAPHQL': 2},
    'tRPC':         {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'TRPC': 2},
    'gRPC-Web':     {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'GRPC_WEB': 2},
    'Swagger':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SWAGGER': 2},
    'OpenAPI':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SWAGGER': 2},

    # 后端框架 (侧重管理面/配置面接口)
    'Django':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'DJANGO_ADMIN': 2, 'DJANGO_API': 1},
    'Spring':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 2, 'SPRING_API': 1},
    'Spring-Boot':  {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 2, 'SWAGGER': 2},
    'Laravel':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'LARAVEL_API': 2},
    'WordPress':    {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'WP_REST': 2, 'WP_ADMIN': 1},
    # ---- 国内前端 ----
    'Taro':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'TARO_API': 2},
    'uni-app':      {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'UNI_API': 2},
    'Ant-Design-Pro':{'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'Vant':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'Element-Plus': {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'Arco-Design':  {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'TDesign':      {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 国内后端 ----
    'ThinkPHP':     {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'THINKPHP_API': 2},
    'Spring-Cloud-Alibaba':{'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 2},
    'Dubbo':        {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Beego':        {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'JFinal':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 国内低代码/CMS ----
    'JeecgBoot':    {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'JEECGBOOT_API': 2},
    'RuoYi':        {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'RUOYI_API': 2},
    'Discuz!':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'DISCUZ_API': 1},
    'Typecho':      {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 国外前端 ----
    'Qwik':         {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'QWIK_LOADER': 2},
    'Preact':       {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Alpine.js':    {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'ALPINE_DATA': 2},
    'htmx':         {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'HTMX_ATTR': 2},
    # ---- 国外后端 ----
    'FastAPI':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'FASTAPI_OPENAPI': 2},
    'Gin':          {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Echo':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Fiber':        {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'NestJS':       {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'NEST_CONTROLLER': 2},
    'Hono':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Elysia':       {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 数据库/BAAS ----
    'Firebase':     {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'FIREBASE_API': 2},
    'Supabase':     {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SUPABASE_CLIENT': 2},
    # ---- 云服务和安全类指纹(无专属JS规则, 走默认路由) ----
    '腾讯云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '华为云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '百度智能云':    {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 国内云厂商(大中小全覆盖) ----
    '阿里云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'ALIYUN_API': 1},
    '金山云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'UCloud':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '七牛云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'QINIU_API': 1},
    '又拍云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '天翼云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '移动云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '京东云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '火山引擎':     {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'VOLC_API': 1},
    '网易云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '青云科技':     {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '新浪云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '灵雀云':       {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '时速云':       {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '博云':         {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '浪潮云':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '用友云':       {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    '金蝶云':       {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 国外云服务 ----
    'DigitalOcean': {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Fly.io':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Render':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'ModSecurity':  {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 0, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'AWS-WAF':      {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 0, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'F5':           {'RE_API': 0, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 0, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # ---- 扩充 : 原先无路由条目的后端/前端/CMS 指纹 ----
    #   基础设施类指纹(Nginx/IIS/Tomcat/CDN/WAF/云厂商)刻意**不设路由条目** ——
    #   它们不决定 JS 分析策略, 命中与否不影响提取行为, 这属于设计正确而非遗漏。
    'Express':      {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 1, 'RE_SSE': 1},
    'Koa':          {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 1, 'RE_SSE': 1},
    'Rails':        {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'ASP.NET':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 1, 'RE_SSE': 0},
    'PHP':          {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Flask':        {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 1, 'RE_SSE': 1},
    'Symfony':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Yii':          {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'CodeIgniter':  {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'CakePHP':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Micronaut':    {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 1},
    'Quarkus':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 1},
    'Solon':        {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'SPRING_ACTUATOR': 1},
    'SolidJS':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'Vite':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'JWT':          {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'OAuth2':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Keycloak':     {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Shiro':        {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Sa-Token':     {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Spring-Security': {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Auth0':        {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Okta':         {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # CMS: 侧重 REST 面与管理面路径
    'Drupal':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'DRUPAL_API': 2},
    'Joomla':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'JOOMLA_API': 2},
    'Strapi':       {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'STRAPI_API': 2},
    'Directus':     {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Ghost':        {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'GHOST_API': 2},
    'Shopify':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'Magento':      {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0},
    'WooCommerce':  {'RE_API': 2, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0,
                     'WP_REST': 2},
    'DedeCMS':      {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'PHPCMS':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'EmpireCMS':    {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Z-Blog':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'Ecshop':       {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'PrestaShop':   {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'OpenCart':     {'RE_API': 1, 'RE_WRITE': 0, 'RE_TEMPLATE_URL': 0,
                     'RE_ROUTE': 0, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    # UI 库: 只影响路由/模板提取, 不改变 API 面
    'Bootstrap':    {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Element-UI':   {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'VUE_ROUTER': 1},
    'Layui':        {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 0, 'RE_WS': 0, 'RE_SSE': 0},
    'uView':        {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 0, 'RE_SSE': 0,
                     'UNI_API': 1},
    'MUI':          {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Vuetify':      {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'VUE_ROUTER': 1},
    'Quasar':       {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 2, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'VUE_ROUTER': 1},
    'Naive-UI':     {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    # API 风格 / 构建工具: 纯 JS 阶段判定, 只开启对应提取器
    'REST':         {'RE_API': 2, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Webpack':      {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 2, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Rollup':       {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 2, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'esbuild':      {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 2, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},
    'Parcel':       {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 2, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1},

    # Hotwire / Turbo(Rails 全栈): `Turbo.visit('/x')` 的 URL 是**前端路由**(非接口) → 归 routes
    'Turbo':        {'RE_API': 1, 'RE_WRITE': 1, 'RE_ROUTE': 1, 'TURBO_VISIT': 2},

    # 默认兜底 (未命中任何指纹时, 启用全部规则)
    # 移除 GRAPHQL / GRPC_WEB / TRPC / SWAGGER 的预置值(=1)。
    #   现在这些能力开关只由命中的指纹通过 ROUTE_RULES 抬升, 未命中即为 0(关闭)。
    # 补入 SENSITIVE / RE_BASEURL / RE_GRPC_METHOD(与技术栈无关的核心基线能力, 兜底常开)。
    #   这四个键此前不在任何 ROUTE_RULES 条目中, 导致 deep_analyze 里
    #   `if 'SENSITIVE' in enabled` 等条件恒为假 —— 即 40 条敏感信息正则、
    #   baseURL 提取、gRPC 方法提取从未执行过。它们属于与技术栈无关的核心能力,
    #   应作为基线常开。
    '_DEFAULT':     {'RE_API': 1, 'RE_WRITE': 1, 'RE_TEMPLATE_URL': 1,
                     'RE_ROUTE': 1, 'RE_CHUNK': 1, 'RE_LAZY': 1, 'RE_WS': 1, 'RE_SSE': 1,
                     'RE_BASEURL': 1, 'RE_GRPC_METHOD': 1, 'SENSITIVE': 1},
}

# 2.2 指纹专属提取正则表
# 背景: `ROUTE_RULES` 为 33 个技术栈定义了专属开关(SPRING_ACTUATOR / WP_REST /
# VUE_ROUTER / GRAPHQL / TRPC / JEECGBOOT_API …), 但**全项目没有任何一处读取它们** ——
# `deep_analyze` 只判断 13 个与技术栈无关的通用 `RE_*` 开关。结果是:
#   · 路由权重表 100% 沦为装饰;
#   · README 承诺的「按指纹路由启用专属规则集」完全未实现;
#   · 33 个开关是死配置。
# 本表把每个专属开关接到**真实的提取行为**上: 命中对应指纹后, 该开关被
# `ROUTE_RULES` 抬升进 `enabled`, `deep_analyze` 据此启用这里定义的专属正则。
# 约定: 每条正则**必须**有一个捕获组, group(1) 即提取出的路径/端点。
ROUTE_EXTRA_PATTERNS = {
    # ---- Spring 系 ----
    'SPRING_ACTUATOR': [re.compile(r'["\'`](/actuator/[A-Za-z0-9_\-/]*)["\'`]')],
    'SPRING_API':      [re.compile(r'["\'`](/[A-Za-z0-9_\-/]*(?:spring|boot)[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- API 文档面 ----
    'SWAGGER':         [re.compile(r'["\'`](/[^"\'`]{0,60}(?:swagger|api-docs|openapi)[^"\'`]{0,60})["\'`]')],
    'FASTAPI_OPENAPI': [re.compile(r'["\'`](/openapi\.json|/docs|/redoc)["\'`]')],
    # ---- WordPress 系 ----
    'WP_REST':         [re.compile(r'["\'`](/wp-json/[A-Za-z0-9_\-/]*)["\'`]')],
    'WP_ADMIN':        [re.compile(r'["\'`](/wp-admin/[A-Za-z0-9_\-/.]*)["\'`]')],
    # ---- Django ----
    'DJANGO_ADMIN':    [re.compile(r'["\'`](/admin/[A-Za-z0-9_\-/]*)["\'`]')],
    'DJANGO_API':      [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- PHP 系 CMS ----
    'LARAVEL_API':     [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    'THINKPHP_API':    [re.compile(r'["\'`](/index\.php/[A-Za-z0-9_\-/]*)["\'`]')],
    'DISCUZ_API':      [re.compile(r'["\'`](/[A-Za-z0-9_\-/]*\.php\?mod=[A-Za-z0-9_=&]*)["\'`]')],
    'JOOMLA_API':      [re.compile(r'["\'`](/index\.php\?option=com_[A-Za-z0-9_=&]*)["\'`]')],
    'DRUPAL_API':      [re.compile(r'["\'`](/jsonapi/[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- 国内低代码平台 ----
    'JEECGBOOT_API':   [re.compile(r'["\'`](/(?:sys|jeecg-boot|jmreport)/[A-Za-z0-9_\-/]*)["\'`]')],
    'RUOYI_API':       [re.compile(r'["\'`](/(?:system|monitor|tool|prod-api)/[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- 小程序 / 跨端 ----
    'TARO_API':        [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    'UNI_API':         [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- 前端路由 / 状态 ----
    'VUE_ROUTER':      [re.compile(r'path\s*:\s*["\'`](/[A-Za-z0-9_\-/:]*)["\'`]')],
    'PINIA':           [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    'SSR_EXTRA':       [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    # ---- API 架构风格 ----
    'GRAPHQL':         [re.compile(r'["\'`](/[A-Za-z0-9_\-/]*graphql[A-Za-z0-9_\-/]*)["\'`]')],
    'TRPC':            [re.compile(r'["\'`]([A-Za-z][A-Za-z0-9_]{1,30}\.[a-z][A-Za-z0-9_]{1,30}\.[a-zA-Z]\w{1,30})["\'`]')],
    'GRPC_WEB':        [re.compile(r'["\'`](/[A-Za-z][A-Za-z0-9_.]*\.[A-Z][A-Za-z0-9]*/[A-Za-z][A-Za-z0-9_]*)["\'`]')],
    'NEST_CONTROLLER': [re.compile(r'@Controller\s*\(\s*["\'`]([^"\'`]*)["\'`]')],
    'ANGULAR_RESOURCE':[re.compile(r'\$resource\s*\(\s*["\'`]([^"\'`]+)["\'`]')],
    # ---- Hotwire / Turbo(前端路由) ----
    'TURBO_VISIT':     [re.compile(r'Turbo\.visit\s*\(\s*["\'`]([^"\'`]+)["\'`]')],
    # ---- SSR 框架专属 ----
    'NUXT_FETCH':      [re.compile(r'\$fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]')],
    'REMIX_LOADER':    [re.compile(r'["\'`](/[A-Za-z0-9_\-/]*\.data)["\'`]')],
    'QWIK_LOADER':     [re.compile(r'["\'`](/build/[A-Za-z0-9_\-/.]*)["\'`]')],
    # ---- 轻量前端 ----
    'ALPINE_DATA':     [re.compile(r'x-data\s*=\s*["\']([^"\']{3,200})["\']')],
    'HTMX_ATTR':       [re.compile(r'hx-(?:get|post|put|delete|patch)\s*=\s*["\']([^"\']+)["\']')],
    # ---- 云 / BaaS 后端 ----
    'ALIYUN_API':      [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    'QINIU_API':       [re.compile(r'(https?://[a-z0-9.\-]*qiniucdn\.com/[^\s"\'`]*)')],
    'VOLC_API':        [re.compile(r'(https?://[a-z0-9.\-]*\.volces\.com/[^\s"\'`]*)')],
    'FIREBASE_API':    [re.compile(r'(https?://[a-z0-9.\-]*\.firebaseio\.com[^\s"\'`]*)')],
    'SUPABASE_CLIENT': [re.compile(r'["\'`](https://[a-z0-9]+\.supabase\.co[^\s"\'`]*)["\'`]')],
    # ---- CMS 平台 API ----
    'STRAPI_API':      [re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]*)["\'`]')],
    'GHOST_API':       [re.compile(r'["\'`](/ghost/api/[A-Za-z0-9_\-/]*)["\'`]')],
}

# ---- 迁移自原 EXTRA_JS_PATTERNS(按指纹名) —— 统一到本表(按开关名) ----
#   同名者(21): 追加其'按指纹名'版正则(原两套各存一份 → 合并为一);
ROUTE_EXTRA_PATTERNS['ALIYUN_API'].append(re.compile('aliyun\\.(?:ecs|rds|slb|cdn|oss|vpc)\\.'))
ROUTE_EXTRA_PATTERNS['ALPINE_DATA'].append(re.compile('x-data\\s*=\\s*["\\\']([^"\\\'`]+)["\\\'"]|Alpine\\.data\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'"]'))
ROUTE_EXTRA_PATTERNS['DISCUZ_API'].append(re.compile('/api/\\w+\\.php|forum\\.php\\?mod='))
ROUTE_EXTRA_PATTERNS['DJANGO_API'].append(re.compile('/api/v\\d+/|django_rest_framework'))
ROUTE_EXTRA_PATTERNS['FASTAPI_OPENAPI'].append(re.compile('/openapi\\.json|/docs|/redoc'))
ROUTE_EXTRA_PATTERNS['FIREBASE_API'].append(re.compile('firebase\\.(?:app|auth|firestore|database|storage|functions)'))
ROUTE_EXTRA_PATTERNS['HTMX_ATTR'].append(re.compile('hx-(?:get|post|put|delete|patch)\\s*=\\s*["\\\'`]([^"\\\'`]+)["\\\'"]'))
ROUTE_EXTRA_PATTERNS['JEECGBOOT_API'].append(re.compile('/sys/(?:permission|role|user|dict|depart)/|/jeecgboot/'))
ROUTE_EXTRA_PATTERNS['LARAVEL_API'].append(re.compile('/api/(?:users|orders|products|auth|login|register)/'))
ROUTE_EXTRA_PATTERNS['NEST_CONTROLLER'].append(re.compile('@Controller\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'"]'))
ROUTE_EXTRA_PATTERNS['NUXT_FETCH'].append(re.compile('\\$fetch\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]'))
ROUTE_EXTRA_PATTERNS['QWIK_LOADER'].append(re.compile('qwikloader|qwik-city|useQwik'))
ROUTE_EXTRA_PATTERNS['RUOYI_API'].append(re.compile('/system/(?:user|role|dept|post|dict|config|notice|operlog|logininfor)/|/api/[\\w/]+'))
ROUTE_EXTRA_PATTERNS['SPRING_ACTUATOR'].append(re.compile('/actuator/(?:health|info|env|metrics|beans|configprops|loggers|threaddump|heapdump|jolokia)'))
ROUTE_EXTRA_PATTERNS['SUPABASE_CLIENT'].append(re.compile('supabase\\.from\\s*\\(\\s*["\\\']([^"\\\']+)["\\\']\\s*\\)|supabase\\.auth'))
ROUTE_EXTRA_PATTERNS['TARO_API'].append(re.compile('Taro\\.(?:request|uploadFile|downloadFile)\\s*\\(\\s*\\{[^}]*url\\s*:\\s*["\\\'`]([^"\\\'`]+)["\\\'"]'))
ROUTE_EXTRA_PATTERNS['THINKPHP_API'].append(re.compile('(?:/api/|/index\\.php/)[\\w/]+|\\.php\\?s=/[\\w/]+'))
ROUTE_EXTRA_PATTERNS['UNI_API'].append(re.compile('uni\\.(?:request|uploadFile|navigateTo)\\s*\\(\\s*\\{[^}]*url\\s*:\\s*["\\\'`]([^"\\\'`]+)["\\\'"]'))
ROUTE_EXTRA_PATTERNS['VOLC_API'].append(re.compile('open\\.volcengine\\.api|volcengine\\.com'))
ROUTE_EXTRA_PATTERNS['WP_ADMIN'].append(re.compile('/wp-admin/(?:admin-ajax\\.php|admin-post\\.php|edit\\.php|post\\.php)'))
ROUTE_EXTRA_PATTERNS['WP_REST'].append(re.compile('/wp-json/wp/v2/(?:posts|pages|users|media|comments|types|taxonomies|tags|categories)/\\d+'))
#   新名者: 新增开关。
ROUTE_EXTRA_PATTERNS.update({
    'ALIYUN_OSS': [re.compile('oss-cn-[a-z0-9-]+\\.aliyuncs\\.com|\\.oss-')],
    'ALPINE_EVENT': [re.compile('x-on:\\w+|@\\w+\\s*=\\s*["\\\'`]([^"\\\'`]+)["\\\'"]')],
    'ANGULAR_HTTP': [re.compile('\\.(?:get|post|put|delete|patch)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]\\s*,')],
    'ANGULAR_ROUTE': [re.compile('RouterModule\\.forRoot\\s*\\(\\s*\\[(.*?)\\]')],
    'APOLLO_CLIENT': [re.compile('ApolloClient|useQuery\\s*\\(|useMutation\\s*\\(')],
    'DISCUZ_HOOK': [re.compile('hook/\\w+|plugin\\.php\\?id=')],
    'DJANGO_URL': [re.compile('url\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]\\s*,\\s*')],
    'FASTAPI_ROUTE': [re.compile('@app\\.(?:get|post|put|delete|patch)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'"]')],
    'FIREBASE_PROJECT': [re.compile('[a-z0-9-]+\\.firebaseapp\\.com|firestore\\.googleapis\\.com')],
    'GRAPHQL_QUERY': [re.compile("(?:query|mutation)\\s+\\w+\\s*\\{|gql\\s*[`\\']([\\s\\S]*?)[`\\']")],
    'HTMX_TARGET': [re.compile('hx-target\\s*=\\s*["\\\'`]([^"\\\'`]+)["\\\'"]|hx-trigger\\s*=\\s*["\\\'`]([^"\\\'`]+)["\\\'"]')],
    'JEECGBOOT_MENU': [re.compile('(/api|/jeecg)/[\\w/]+')],
    'LARAVEL_ROUTE': [re.compile('Route::(?:get|post|put|delete|patch|any)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]')],
    'NEST_MAPPING': [re.compile('@(?:Get|Post|Put|Delete|Patch|All)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'"]')],
    'NEXT_API_ROUTE': [re.compile('export\\s+(?:async\\s+)?function\\s+(?:GET|POST|PUT|DELETE|PATCH)\\s*\\(')],
    'NEXT_APP_ROUTER': [re.compile('app/\\(.*\\)/page\\.')],
    'NUXT_API': [re.compile('(?:server|api)/.*\\.(?:get|post|put|delete)\\.ts')],
    'QCLOUD_API': [re.compile('qcloud\\.(?:cvm|cdb|clb|cdn|cos)\\.')],
    'QCLOUD_COS': [re.compile('cos\\.[a-z0-9-]+\\.myqcloud\\.com|<bucket>\\.cos\\.')],
    'QINIU_CDN': [re.compile('qiniudn\\.com|qiniucdn\\.com|clouddn\\.com|qbox\\.me')],
    'QINIU_UPLOAD': [re.compile('upload\\.qiniup\\.com|up-z\\d+\\.qiniup\\.com')],
    'QWIK_ROUTE': [re.compile('qwik\\.json|_qwik-city_')],
    'RUOYI_MENU': [re.compile('/api/[\\w/]+')],
    'SPRING_MAPPING': [re.compile('@(?:Get|Post|Put|Delete|Patch)Mapping\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]')],
    'SUPABASE_RPC': [re.compile('supabase\\.rpc\\s*\\(\\s*["\\\']([^"\\\']+)["\\\']\\s*\\)')],
    'TARO_ROUTE': [re.compile('pages/[\\w-]+/index(?:\\.(?:vue|tsx|jsx))?')],
    'THINKPHP_ROUTE': [re.compile('Route::(?:get|post|put|delete|patch|any|rule)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'"]')],
    'TRPC_PROCEDURE': [re.compile('\\.(?:query|mutation|subscription)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]')],
    'TRPC_ROUTER': [re.compile('createTRPCRouter|router\\s*=\\s*\\{')],
    'UNI_PAGES': [re.compile('pages\\.json|pages/[\\w-]+/index')],
    'VOLC_CDN': [re.compile('volcdns\\.com|bytecdn\\.cn|bytedance\\.com')],
    'VUEX_STORE': [re.compile('store\\s*\\.\\s*(?:dispatch|commit)\\s*\\(\\s*["\\\'`]([^"\\\'`]+)["\\\'`]')],
    'VUE_ROUTER_PATH': [re.compile('path\\s*:\\s*["\\\'`]([^"\\\'`]+)["\\\'`]\\s*,\\s*component')],
})
#   迁移开关: 让原 EXTRA_JS 指纹在 ROUTE_RULES 中启用上述开关 → 经 get_extra_route_patterns 注入。
for _fp, _sws in {
    'Next.js': ('NEXT_API_ROUTE', 'NEXT_APP_ROUTER'),
    'Nuxt': ('NUXT_API', 'NUXT_FETCH'),
    'Vue': ('VUE_ROUTER_PATH', 'VUEX_STORE'),
    'Angular': ('ANGULAR_HTTP', 'ANGULAR_ROUTE'),
    'GraphQL': ('GRAPHQL_QUERY', 'APOLLO_CLIENT'),
    'tRPC': ('TRPC_PROCEDURE', 'TRPC_ROUTER'),
    'Django': ('DJANGO_URL', 'DJANGO_API'),
    'Spring': ('SPRING_MAPPING', 'SPRING_ACTUATOR'),
    'Laravel': ('LARAVEL_ROUTE', 'LARAVEL_API'),
    'WordPress': ('WP_REST', 'WP_ADMIN'),
    'Taro': ('TARO_API', 'TARO_ROUTE'),
    'uni-app': ('UNI_API', 'UNI_PAGES'),
    'ThinkPHP': ('THINKPHP_API', 'THINKPHP_ROUTE'),
    'JeecgBoot': ('JEECGBOOT_API', 'JEECGBOOT_MENU'),
    'RuoYi': ('RUOYI_API', 'RUOYI_MENU'),
    'Discuz!': ('DISCUZ_API', 'DISCUZ_HOOK'),
    'Qwik': ('QWIK_LOADER', 'QWIK_ROUTE'),
    'Alpine.js': ('ALPINE_DATA', 'ALPINE_EVENT'),
    'htmx': ('HTMX_ATTR', 'HTMX_TARGET'),
    'FastAPI': ('FASTAPI_OPENAPI', 'FASTAPI_ROUTE'),
    'NestJS': ('NEST_CONTROLLER', 'NEST_MAPPING'),
    'Firebase': ('FIREBASE_API', 'FIREBASE_PROJECT'),
    'Supabase': ('SUPABASE_CLIENT', 'SUPABASE_RPC'),
    '阿里云': ('ALIYUN_OSS', 'ALIYUN_API'),
    '腾讯云': ('QCLOUD_COS', 'QCLOUD_API'),
    '七牛云': ('QINIU_CDN', 'QINIU_UPLOAD'),
    '火山引擎': ('VOLC_CDN', 'VOLC_API'),
}.items():
    ROUTE_RULES.setdefault(_fp, {})
    for _s in _sws:
        ROUTE_RULES[_fp][_s] = max(ROUTE_RULES[_fp].get(_s, 0), 1)

# 预编译: 把 ROUTE_EXTRA_PATTERNS 中的条目按开关名缓存为 (name, compiled)
ROUTE_EXTRA_COMPILED = {k: tuple(v) for k, v in ROUTE_EXTRA_PATTERNS.items()}

# `ROUTE_EXTRA_PATTERNS` 中**产出前端路由/非接口值**的模式名。
# 判据: 形态(是否以 `/` 开头)区分不了前端路由与接口 —— 必须按模式名判定。
# 这批模式此前被当作"已正确的兄弟路径"参照 —— 其实它有**同一类缺陷**, 只是被门控遮住:
#   `VUE_ROUTER` 只在 `Vue` 指纹命中时才注入, 而本站的 `Vue` 此前只在 JS 阶段被识别,
#   注入时机早于补判 → 该模式从未生效, 缺陷因此从未暴露。
#   修好注入时序后立刻显形: 路由表里的 `/about`、`/account` 等被写进 apis(实测 +89 条)。
ROUTE_EXTRA_ROUTE_NAMES = frozenset({
    'VUE_ROUTER',       # path:"/course/:id" → Vue Router 前端路由
    'QWIK_LOADER',      # /build/... → 构建产物
    'REMIX_LOADER',     # /xxx.data → 路由级数据加载端点(非 API)
    'TRPC',             # a.b.c → tRPC 过程名
    'ALPINE_DATA',      # x-data → 组件状态表达式
    'NEST_CONTROLLER',  # @Controller("x") → 装饰器参数(常无前导 /)
    # ---- 合并自原 EXTRA_JS_PATTERN_NAMES(同一"产出前端路由/非接口值"语义) ----
    'VUE_ROUTER_PATH',  # path:"/course/:id" → Vue Router 前端路由
    'ANGULAR_ROUTE',    # RouterModule.forRoot([...])
    'NEXT_APP_ROUTER',  # app/(group)/page.tsx
    'TARO_ROUTE',       # pages/xxx/index
    'UNI_PAGES',        # pages.json / pages/xxx/index
    'QWIK_ROUTE',       # qwik.json / _qwik-city_
    'NUXT_API',         # server/api/xxx.get.ts —— 服务端路由文件, 非客户端接口
    'TURBO_VISIT',      # Turbo.visit('/x') → Hotwire 页面导航(前端路由, 非接口)
})

def get_extra_route_patterns(enabled):
    """按启用的路由开关, 返回应生效的指纹专属提取正则列表

    Args:
        enabled: `get_enabled_rules(route)` 的结果(规则名列表)
    Returns:
        [(switch_name, compiled_pattern), ...]
    """
    out = []
    if not enabled:
        return out
    eset = set(enabled)
    for switch, pats in ROUTE_EXTRA_COMPILED.items():
        if switch in eset:
            for p in pats:
                out.append((switch, p))
    return out

# 2.5 强信号表
# 背景: 有些指纹的判定依据是**一条决定性的响应头或页面标记**, 例如
#   `X-Powered-By: ThinkPHP` / `X-AspNet-Version: 4.0.30319` / `Server: Apache-Coyote/1.1`
#   `<meta name="generator" content="WordPress 6.4">`
# 这类指纹的其余规则往往有 4~5 条(HTML 里通常一条都不出现), 按比例阈值
#   conf = 1/5 = 0.20 < 0.3
# 会被判为"未命中" —— 但这条信号本身就是百分之百的确定信号。
# 因此单独维护一张**精确匹配**的强信号表: 命中任意一条即判定该指纹, 置信度 1.0。
# 匹配对象是 `响应头 + '\n' + HTML`。设计约束:
#   · 模式必须**足够紧**, 不能出现 `Server:\s*Apache` 这种会把 `Apache-Coyote`
#     (Tomcat) 也算进来的宽模式;
#   · 同一信号只能归属一个指纹, 避免一对多误判。
FP_STRONG_SIGNALS = {
    # ---- Web 服务器 / 中间件 ----
    'Nginx':        [r'Server:\s*nginx(?:/|$|\s)'],
    'Apache':       [r'Server:\s*Apache/(?:2|1)\.'],
    'Tomcat':       [r'Server:\s*Apache-Coyote/', r'Server:\s*Apache Tomcat'],
    'IIS':          [r'Server:\s*Microsoft-IIS/'],
    'OpenResty':    [r'Server:\s*openresty'],
    'Caddy':        [r'Server:\s*Caddy(?:/|$|\s)'],
    'Jetty':        [r'Server:\s*Jetty'],
    'Undertow':     [r'Server:\s*undertow'],
    'Kestrel':      [r'Server:\s*Kestrel'],
    'Gunicorn':     [r'Server:\s*gunicorn'],
    'uWSGI':        [r'Server:\s*uWSGI'],
    'LiteSpeed':    [r'Server:\s*LiteSpeed'],
    'Traefik':      [r'Server:\s*Traefik'],
    'Envoy':        [r'Server:\s*envoy', r'X-Envoy-'],
    'Varnish':      [r'X-Varnish:', r'Via:\s*[^\n]*varnish'],
    'GlassFish':    [r'Server:\s*GlassFish'],
    'WebLogic':     [r'Server:\s*WebLogic'],
    'JBoss':        [r'Server:\s*JBoss', r'X-Powered-By:\s*JBoss'],
    'WildFly':      [r'Server:\s*WildFly'],
    # ---- 后端框架 / 语言 ----
    'ThinkPHP':     [r'X-Powered-By:\s*ThinkPHP'],
    'ASP.NET':      [r'X-AspNet-Version:', r'X-AspNetMvc-Version:', r'X-Powered-By:\s*ASP\.NET',
                     r'id="__VIEWSTATE"', r'name="__VIEWSTATE"', r'__EVENTVALIDATION'],
    'Express':      [r'X-Powered-By:\s*Express'],
    'PHP':          [r'X-Powered-By:\s*PHP/', r'Set-Cookie:\s*PHPSESSID'],
    'Laravel':      [r'Set-Cookie:\s*laravel_session'],
    'Rails':        [r'X-Runtime:\s*[\d.]+', r'Set-Cookie:\s*_rails'],
    'Django':       [r'Server:\s*WSGIServer', r'Set-Cookie:\s*csrftoken'],
    'Flask':        [r'Server:\s*Werkzeug'],
    'WordPress':    [r'X-Powered-By:\s*WordPress', r'Link:\s*<[^>]*\?rest_route=',
                     r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress'],
    'GraphQL':      [r'X-Powered-By:\s*graphql'],
    # 前端 SPA 生产构建在 HTML 阶段近乎空(<div id="root"> 等),
    #   仅靠 body 规则比例(React 6 条 body 规则, 单标记 1/6=0.17<0.3)必漏判。
    #   这些框架的决定性标记(打包产物里的模块导入 / 构造函数 / 脚手架路径)即强信号,
    #   一条命中即判定, 不受比例阈值约束。
    'React':        [r'from\s*["\']react["\']', r'React\.createElement'],
    'Vue':          [r'vue\.min\.js', r'vue\.js', r'__VUE__', r'data-v-'],
    'Vue3':         [r'vue\.global\.js', r'vue\.runtime\.esm-bundler', r'createApp\s*\(',
                     r'from\s*["\']vue["\']'],
    'Angular':      [r'<app-root'],
    'Vite':         [r'__vite__', r'import\.meta\.hot', r'\.vite/'],
    # 前端框架的"根容器 id"是决定性标记 —— 页面里出现
    #   `<div id="__next">` / `<div id="__nuxt">` 就只可能是对应框架渲染的,
    #   比任何关键字计数都可靠。此前它们只是 body 规则之一, 会被其余规则稀释。
    'Next.js':      [r'X-Powered-By:\s*Next\.js', r'id=["\']__next["\']', r'__NEXT_DATA__', r'__next_f'],
    'Nuxt':         [r'X-Powered-By:\s*Nuxt', r'id=["\']__nuxt["\']', r'window\.__NUXT__', r'/_nuxt/'],
    'Strapi':       [r'X-Powered-By:\s*Strapi',
                     r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Strapi'],
    'Spring':       [r'X-Application-Context:'],
    # Spring-Boot 此前**没有**强信号 —— 一个只带
    #   `X-Application-Context` 头(或只有 Whitelabel 错误页)的 Boot 站点,
    #   在 4 条 body + 1 条 header 的评分下比例不达标, 只能被识别成泛化的 "Spring",
    #   拿不到 Boot 专属的 actuator / springdoc 路由开关。
    'Spring-Boot':  [r'X-Application-Context:', r'Whitelabel Error Page'],
    'Spring-Cloud-Alibaba': [r'/nacos/v1/', r'nacos-config', r'X-Nacos-'],
    # ---- 认证 / 会话 ----
    'Shiro':        [r'Set-Cookie:\s*rememberMe=deleteMe'],
    'Sa-Token':     [r'Set-Cookie:\s*SATOKEN'],
    # JSESSIONID 只是 Java Servlet 容器的通用会话 cookie,
    #   把它当 Spring-Security 的强信号会把**任何 Java Web 应用**都标成 Spring Security。
    #   真正的 Spring Security 特征是它注入的 CSRF cookie `XSRF-TOKEN`。
    #   JSESSIONID 已下沉到 FP_COOKIE_SIGNALS 作低置信度兜底(见该表注释)。
    'Spring-Security': [r'Set-Cookie:\s*XSRF-TOKEN'],
    'Keycloak':     [r'Set-Cookie:\s*KEYCLOAK_'],
    # ---- 云 / CDN / WAF ----
    'Cloudflare':   [r'CF-Ray:', r'Server:\s*cloudflare'],
    'CloudFront':   [r'X-Amz-Cf-Id:', r'Via:\s*[^\n]*CloudFront'],
    'Akamai':       [r'Server:\s*AkamaiGHost', r'X-Akamai-'],
    'AWS':          [r'Server:\s*AmazonS3', r'X-Amz-Request-Id:'],
    'Vercel':       [r'Server:\s*Vercel', r'X-Vercel-'],
    'Netlify':      [r'Server:\s*Netlify', r'X-Nf-Request-Id:'],
    'Imperva':      [r'X-Iinfo:', r'Server:\s*Imperva'],
    'Sucuri':       [r'X-Sucuri-Id:', r'Server:\s*Sucuri'],
    '安全狗':        [r'Server:\s*Safe3WAF', r'X-Powered-By:\s*Safe3'],
    '长亭':          [r'Server:\s*Chaitin'],
    '阿里云盾':       [r'Server:\s*Aliyun', r'X-Server-Id:\s*aliyun'],
    '腾讯云WAF':     [r'Server:\s*Tencent-Cloud-WAF'],
    '创宇盾':        [r'Server:\s*Knownsec'],
    'ModSecurity':  [r'Server:\s*ModSecurity', r'Mod_Security'],
    'F5':           [r'Server:\s*BIG-IP', r'X-WA-Info:'],
    'AWS-WAF':      [r'X-Amzn-RequestId:.*waf', r'Server:\s*awselb'],
    'Wallarm':      [r'Server:\s*nginx-wallarm', r'X-Wallarm-'],
    # ---- 页面级强信号 (generator meta / 决定性标记) ----
    'Joomla':       [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla'],
    'Drupal':       [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal',
                     r'X-Generator:\s*Drupal'],
    'Magento':      [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Magento'],
    'PrestaShop':   [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']PrestaShop'],
    'OpenCart':     [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']OpenCart'],
    'Typecho':      [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Typecho'],
    'Discuz!':      [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Discuz'],
    'DedeCMS':      [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']DedeCMS',
                     r'Powered by <a[^>]*>DedeCMS'],
    'PHPCMS':       [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']PHPCMS'],
    'EmpireCMS':    [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']EmpireCMS',
                     r'Powered by <a[^>]*>EmpireCMS'],
    'Ghost':        [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost'],
    'Z-Blog':       [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Z-Blog'],
}

# 会话/令牌类响应头 → 强信号(仅在无其它指纹命中时作为兜底)
FP_COOKIE_SIGNALS = {
    'Spring':   [r'Set-Cookie:\s*JSESSIONID'],
    'Tomcat':   [r'Set-Cookie:\s*JSESSIONID'],
}

# 3. 指纹识别引擎

# 命中阈值: 至少要命中 30% 的可评分规则
FP_HIT_THRESHOLD = 0.3

def _conf_cap(max_score):
    """按"可评分规则条数"给置信度封顶 —— 证据越少, 上限越低。

    `conf = score / max_score` 在 max_score=1 时**一次命中即 1.0(满置信)**。
    实测指纹库里 `Deno`(js 规则仅 `Deno\\.` 一条) 与 `Onsen UI`(仅 `ons\\.` 一条)
    各自只有一条规则, 于是页面里出现一次 `ons.` 就报 "Onsen UI (100%)" ——
    置信度是给人做决策用的, 不能把"证据量只有 1 条"渲染成"100% 确定"。

    封顶值刻意不低于 FP_HIT_THRESHOLD(0.3): 弱证据仍会被记录、仍参与路由门控,
    **能力不减**, 只是展示出来的置信度变得诚实。
    """
    if max_score <= 1:
        return 0.5
    if max_score == 2:
        return 0.8
    return 1.0

# JS 阶段的"补判"阈值。规则与 HTML 阶段不同:
#   · 该指纹**没有** body/headers/url 规则 → 它在 HTML 阶段结构上不可能命中,
#     JS 阶段就是它唯一的机会 → 用常规阈值 FP_HIT_THRESHOLD。
#   · 该指纹**有** HTML 规则 → 说明 HTML 阶段已经判过一次且没中, 此时再靠 JS 补判
#     就需要更强的证据(60% 的 js 规则), 否则"只凭一句 useState 就判成 React"。
FP_JS_STRONG_THRESHOLD = 0.6

def _score_rules(rules, body_text, headers_str, url_path, include_js=False, js_text=''):
    """对单条指纹规则评分

    `js` 规则**不再计入 HTML 阶段的分母**。

    现在 HTML 阶段分母只统计 body / headers / url；`js` 规则改由
    `fingerprint_from_js()` 在 JS 分析阶段独立评分（include_js=True 时才参与）。

    Returns:
        (score, max_score): 命中数 / 可评分规则总数
    """
    score = 0
    max_score = 0
    # 大小写等价模式去重(re.I 下 'redis' 与 'Redis' 等价) —— 覆盖**外部** --fingerprint-db
    #   引入的重复(内置表已在 `_normalize_rule_patterns` 入口归一)。见 `_uniq_patterns`。
    if rules.get('body'):
        _p = _uniq_patterns(rules['body'])
        max_score += len(_p)
        for pat in _p:
            if re.search(pat, body_text, re.S | re.I):
                score += 1
    if rules.get('headers'):
        _p = _uniq_patterns(rules['headers'])
        max_score += len(_p)
        for pat in _p:
            if re.search(pat, headers_str, re.I):
                score += 1
    if rules.get('url'):
        _p = _uniq_patterns(rules['url'])
        max_score += len(_p)
        for pat in _p:
            if re.search(pat, url_path, re.I):
                score += 1
    if include_js and rules.get('js') and js_text:
        _p = _uniq_patterns(rules['js'])
        max_score += len(_p)
        for pat in _p:
            if re.search(pat, js_text, re.I):
                score += 1
    return score, max_score

def merge_route(route, name):
    """把某条指纹的路由权重并入 route(就地修改, 取 max)

    """
    if name in ROUTE_RULES:
        for rule, weight in ROUTE_RULES[name].items():
            route[rule] = max(route.get(rule, 0), weight)
    return route

def _headers_to_text(headers_dict):
    """把响应头拍平成可正则匹配的文本, 并**拆分重复头**。

    实测本地自建目标(BaseHTTPRequestHandler 会自动加一个 Server 头)就复现了这个漏检:
    Tomcat 明明在响应里, 却因为没有独立成行而未被识别。

    现在按 `, ` 拆分每个头的值, 让每个取值都独立成 `k: v` 一行, 强信号与评分规则
    都能正常命中。拆分只在"看起来是多个取值"时进行, 避免破坏含逗号的正常值
    (如 Content-Type 的 charset 列表)。
    """
    lines = []
    for k, v in (headers_dict or {}).items():
        v = '' if v is None else str(v)
        # 仅当逗号后紧跟"看起来像新取值"的片段时才拆分(避免拆坏 charset=a, b 之类)
        parts = re.split(r',\s*(?=[A-Za-z][\w\-./]*\s*[/;\d]?)', v) if ', ' in v else [v]
        for p in parts:
            lines.append(f'{k}: {p.strip()}')
    return '\n'.join(lines)

def fingerprint_target(base, html_text, headers_dict, fp_rules=None, confirm_overrides=None):
    """
    全量指纹识别: 综合 HTML body + 响应头 + URL 模式
    返回: (命中指纹列表, 置信度字典, 路由规则字典)

    命中逻辑:
    - body 正则: HTML 文本中匹配任一规则即命中
    - headers 正则: 响应头值中匹配任一规则即命中(重复头会被拆分成独立行, 见 _headers_to_text)
    - URL 模式: 路径中匹配特定关键词
    - js 正则: **不参与本阶段评分**(改由 fingerprint_from_js 在 JS 分析阶段处理)

    fp_rules: 可选, 外部合并后的指纹规则(内置+外部), 缺省用模块级 FP_RULES
    confirm_overrides: 可选, {指纹名: 最少命中信号数} —— B4 确认基线(见
        facet.recon.baseline.get_confirm_overrides)。**设了 need 即按"命中信号数
        >= need"覆盖全局比例阈值**(不再看比例): 泛化名词设 >=2 压误报(需多条
        独立信号), 稀有框架设 1 放松召回(比例不足也能确认)。未设 need 的其它指纹
        仍走全局比例阈值 `FP_HIT_THRESHOLD`。强信号 / 会话 cookie 兜底通道
        (权威标记)不受此约束。
    """
    hits = []
    confidence = {}
    route = dict(ROUTE_RULES['_DEFAULT'])  # 默认兜底
    rules_pool = fp_rules if fp_rules is not None else FP_RULES
    known_names = {n for n, _ in rules_pool}
    overrides = confirm_overrides or {}

    # 构造 headers 字符串用于正则匹配
    headers_str = _headers_to_text(headers_dict)
    url_path = urlparse(base).path.lower()

    for name, rules in rules_pool:
        score, max_score = _score_rules(rules, html_text, headers_str, url_path)
        if max_score <= 0 or score <= 0:
            continue
        conf = min(score / max_score, _conf_cap(max_score))
        need = overrides.get(name)
        # B4 确认基线: 未设 need → 走全局比例阈值; 设了 need → 改用"命中信号数 >= need"
        #   (按指纹名覆盖全局阈值)。need>=2 压泛化名误报(需多条独立信号才确认);
        #   need<=1 放松稀有框架召回(比例不足也能确认)。强信号/cookie 通道不在此约束内。
        if (need is None and conf >= FP_HIT_THRESHOLD) or (need is not None and score >= need):
            hits.append(name)
            confidence[name] = round(conf, 2)
            merge_route(route, name)

    # 强信号: 一条决定性响应头 / 页面标记即判定(不受比例阈值约束)
    #   匹配对象是「响应头 + HTML」—— 表内模式都带明确前缀(`Server:` / `<meta ...`),
    #   不会跨域误匹配。
    #   仅对指纹库中确实存在的条目生效, 避免外部指纹库(--fingerprint-db)覆盖时
    #   引入库里没有的名字。
    signal_text = headers_str + '\n' + (html_text or '')
    for name, pats in FP_STRONG_SIGNALS.items():
        if name in confidence or name not in known_names:
            continue
        if any(re.search(p, signal_text, re.I) for p in pats):
            hits.append(name)
            confidence[name] = 1.0
            merge_route(route, name)

    # 会话 cookie 兜底信号 —— FP_COOKIE_SIGNALS 此前定义了但**全项目零调用**,
    #   表里唯一的条目(JSESSIONID)完全没生效。
    #   语义按该表自身注释执行: "仅在无其它指纹命中时作为兜底"。
    #   JSESSIONID 同时属于 Spring 与 Tomcat 且无法区分, 因此:
    #     · 只在 hits 为空时启用 —— 否则任何带 JSESSIONID 的站点都会多报两条无关指纹;
    #     · 只给 0.3 低置信度 —— 明确标注这是"弱证据", 提醒分析师需要人工确认。
    if not hits:
        for name, pats in FP_COOKIE_SIGNALS.items():
            if name not in known_names:
                continue
            if any(re.search(p, signal_text, re.I) for p in pats):
                hits.append(name)
                confidence[name] = 0.3
                merge_route(route, name)

    # 置信度排序
    hits.sort(key=lambda x: confidence.get(x, 0), reverse=True)
    return hits, confidence, route

def fingerprint_from_js(js_texts, fp_rules=None, known_hits=None, route=None, confirm_overrides=None):
    """JS 分析阶段的指纹补判

    HTML 阶段只能看到 body/headers。有一类指纹(构建工具、API 风格)的特征只出现在
    JS 源码里 —— 例如 `tRPC` / `Rollup` / `esbuild` / `Parcel` / `SolidJS` 的 body 规则
    为空, 旧实现让它们"结构性不可能命中"。本函数在 JS 下载完成后按 `js` 规则补判。

    注意: 本阶段**只补判尚未命中的指纹**, 且要求 JS 规则命中比例达标, 避免噪音。

    Args:
        js_texts: 已下载 JS 的文本列表(或单个字符串)
        fp_rules: 指纹库(缺省内置)
        known_hits: 已命中的指纹名(不重复判定)
        route: 可选, 由 `fingerprint_target` 产出的路由字典。传入时, 新命中的指纹会
            经 `merge_route` 抬升各自专属开关, 函数额外返回合并后的 route ——
            这样 `fingerprint_target` + `fingerprint_from_js` 两个公共 API 组合使用时,
            路由权重不会因"JS 阶段补判"而丢失（旧版 `fingerprint_from_js` 只返回
            hits, 导致 tRPC 等纯 JS 框架的专属提取分支永远开不起来）。不传则维持
            旧行为(仅返回 (new_hits, confidence))。
    Returns:
        (new_hits, confidence_dict) 或 (new_hits, confidence_dict, route) (传了 route 时)
    """
    if isinstance(js_texts, str):
        js_texts = [js_texts]
    blob = '\n'.join(t for t in (js_texts or []) if t)
    if not blob:
        return ([], {}) if route is None else ([], {}, route)
    known = set(known_hits or ())
    rules_pool = fp_rules if fp_rules is not None else FP_RULES
    known_names = {n for n, _ in rules_pool}
    overrides = confirm_overrides or {}
    new_hits, confidence = [], {}
    for name, rules in rules_pool:
        if name in known:
            continue
        js_rules = _uniq_patterns(rules.get('js'))
        if not js_rules:
            continue
        # 本阶段**只按 js 规则评分**(大小写等价去重, 见 `_uniq_patterns`)。
        hit = sum(1 for pat in js_rules if re.search(pat, blob, re.I))
        if hit <= 0:
            continue
        # 与 HTML 阶段同一套封顶 —— JS 阶段同样存在"单条 js 规则命中即 100%"的问题
        #   (`Deno: ['Deno\\.']` / `Onsen UI: ['ons\\.']`), 只在 HTML 阶段封顶会让
        #   这两个指纹从 JS 补判通道以满置信度漏回来。
        conf = min(hit / len(js_rules), _conf_cap(len(js_rules)))
        has_html_rules = bool(rules.get('body') or rules.get('headers') or rules.get('url'))
        thresh = FP_JS_STRONG_THRESHOLD if has_html_rules else FP_HIT_THRESHOLD
        need = overrides.get(name)
        # B4: 未设 need → 走比例阈值; 设了 need → 改按命中信号数(与 HTML 阶段一致)。
        if (need is None and conf >= thresh) or (need is not None and hit >= need):
            new_hits.append(name)
            confidence[name] = round(conf, 2)

    # 强信号同样适用于 JS 阶段。
    #   有一类决定性标记只写在 JS 源码里, 从不进 HTML —— 例如 Nacos 控制台路径
    #   `/nacos/v1/console/namespaces`、Vite 的 `__vite__mapDeps`、Next.js 的
    #   `__NEXT_DATA__`。旧实现只在 HTML 阶段跑 FP_STRONG_SIGNALS, 于是这类指纹
    #   仍要跟"碰巧写了几条 body 规则"比比例, 实测在薄响应上直接漏判。
    #   强信号之所以是强信号, 就是因为它单独一条即足以定性 —— 与它出现在
    #   HTML 还是 JS 无关。
    for name, pats in FP_STRONG_SIGNALS.items():
        if name in known or name in confidence or name not in known_names:
            continue
        if any(re.search(p, blob, re.I) for p in pats):
            new_hits.append(name)
            confidence[name] = 1.0

    new_hits.sort(key=lambda x: confidence.get(x, 0), reverse=True)
    if route is not None:
        for name in new_hits:
            merge_route(route, name)
        return new_hits, confidence, route
    return new_hits, confidence

def get_enabled_rules(route):
    """根据路由规则, 返回启用的规则名列表(按权重降序)

    注意: 本函数只返回**成员性**(权重>0)。`deep_analyze` 里的门控判断也是成员性,
    因此权重的实际作用体现在 `ROUTE_RULES` 与 `_DEFAULT` 的**差集**上 ——
    起 `_DEFAULT` 不再预置指纹专属开关, 权重表才真正决定规则子集。
    """
    enabled = [(k, v) for k, v in route.items() if v > 0]
    enabled.sort(key=lambda x: x[1], reverse=True)
    return [k for k, _ in enabled]

# 4. 技术栈专属正则补充 (按指纹动态注入)

# 各技术栈的专属 JS 正则 (在 deep_analyze 阶段按指纹注入)

# 5. 便捷函数


def load_external_fingerprint_db(path):
    """加载外部指纹库JSON, 与内置指纹合并"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            external = json.load(f)
        # 支持两种格式: 列表式 [(name, rules), ...] 或字典式 {name: rules, ...}
        if isinstance(external, list):
            return external
        elif isinstance(external, dict):
            return list(external.items())
        return []
    except Exception as e:
        # 用户显式给了 --fingerprint-db, 失败却静默 = 外部指纹"没生效"零提示(全库审计 L)。
        dbg(f'外部指纹库加载失败({path}): {e}')
        return []

def merge_fingerprints(base_rules, external_rules):
    """合并外部指纹到基础规则, 外部同名覆盖内置"""
    merged = list(base_rules)
    seen = {name for name, _ in merged}
    for name, rules in external_rules:
        if name in seen:
            # 覆盖已有
            for i, (n, _) in enumerate(merged):
                if n == name:
                    merged[i] = (name, rules)
                    break
        else:
            merged.append((name, rules))
            seen.add(name)
    return merged
