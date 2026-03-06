# MFA助手 项目上下文交接文档

## 1. 项目目标
这是一个 Chrome 扩展（MV3），用于在访问指定 MFA 页面时自动显示当前 MFA 验证码，并提供配置管理能力。

核心原则：
- 不在代码中硬编码 MFA 敏感信息（otpauth/secret）
- 用户通过扩展界面自行配置
- 支持二维码自动解析与手动录入

## 2. 当前已实现功能

### 2.1 扩展弹窗（popup）
路径：`popup/`

- 点击扩展图标打开 popup
- 展示“已绑定 MFA”列表
- 每个系统可一键复制当前验证码
- 右上角有“配置”按钮，打开新页签进入配置中心（manage 页面）

### 2.2 配置中心（manage）
路径：`manage/`

- 标题：`MFA助手配置`
- 采用“上传二维码 + 待保存表格 + 已绑定列表”布局

二维码入口：批量解析
- 支持多选图片上传
- 自动解析二维码内容（优先 BarcodeDetector，多策略重试）
- 从 otpauth 中提取 secret
- 默认提取系统名称（issuer/label）

手动新增：
- 待保存列表右上角有“新增”按钮
- 点击后在表格新增一条空行，用户手动填写

待保存列表：
- 表格列：`系统名称`、`mfa_url`、`密钥文本`、`操作`
- 必填列在表头左侧显示红色 `*`（系统名称、mfa_url）
- 无复选框；点击“保存”会保存当前待保存列表全部行
- 支持行内移除、清空和保存
- 对 secret 做去重（避免重复项）

已绑定列表：
- 展示已保存系统
- 支持删除（同时删除对应 secret 覆盖）

### 2.3 内容脚本弹窗（访问目标 mfa_url 页面）
路径：`content/`

- 仅在命中已绑定 `mfa_url` 页面时显示 MFA 弹窗
- 显示验证码、倒计时、复制按钮
- 支持拖拽移动
- 支持自动关闭（登录提交流程/离开页面后）

新增逻辑：
- 若命中页面但该系统尚未绑定 secret，会自动弹出“绑定密钥”面板
- 支持粘贴 secret 或 otpauth 并立即保存生效

## 3. 数据存储（chrome.storage.local）

- `mfaSystems`
  - 类型：Array
  - 结构：`[{ name, mfa_url }]`
  - 用途：系统与目标 MFA 页面绑定

- `mfaSecretOverrides`
  - 类型：Object
  - 结构：`{ [name]: secret }`
  - 用途：系统名到 secret 映射

## 4. 目录结构（当前）

- `manifest.json`
- `content/`
  - `content.js`
  - `content.css`
- `popup/`
  - `popup.html`
  - `popup.js`
  - `popup.css`
- `manage/`
  - `manage.html`
  - `manage.js`
  - `manage.css`
- `README.md`
- `PROJECT_CONTEXT.md`（本文档）

## 5. 关键交互流程

### 配置流程
1. 点击扩展图标 -> popup
2. 点击“配置” -> 新页签打开 manage
3. 通过“二维码批量解析”或“手动添加”加入待保存
4. 在待保存列表完善系统名称、mfa_url
5. 点击“保存”写入本地存储（保存全部待保存项）

### 使用流程
1. 打开某系统 `mfa_url` 页面
2. content 弹窗自动出现
3. 复制验证码使用
4. 登录后弹窗自动关闭

## 6. 历史调整与决策（精简）
- 早期有独立网页原型，后重构为 Chrome 扩展
- 先做了 options 配置页，后改为“popup + 新页签 manage”模式
- 移除了硬编码 secret/otpauth
- 移除了旧 `legacy` 与 `extension` 子目录，当前为根目录直接加载
- 插件名称已统一为：`MFA助手`
- 曾删除内容弹窗“重新绑定”后，又根据需求改为：
  - 在目标页面未绑定密钥时自动弹出绑定面板（目前保留）

## 7. 已知注意事项
- 二维码解析在不同 Chromium 内核浏览器可能存在差异（如 Arc）
- 当前已做兼容：
  - 自动提取文本中的 `otpauth://...`
  - 兼容引号、换行、URL 编码（`otpauth%3A...`）
  - 兼容 `otpauth://totp/...` 与 `otpauth:///totp/...`
  - 图像多策略重试：原图 -> 放大 -> 灰度增强
  - 类型校验放宽：只要 `otpauth://` 且含 `secret` 即可解析
- 若浏览器不支持 `BarcodeDetector`，需要手动输入 secret/otpauth
- 系统名（name）是关联 `mfaSystems` 与 `mfaSecretOverrides` 的键，改名会影响关联

## 8. 新聊天快速接入建议
当你开启新聊天时，可直接提供这三样：
1. 本文档 `PROJECT_CONTEXT.md`
2. 当前问题截图或复现步骤
3. 目标文件范围（如：`manage/` 或 `content/`）

这样可以最快进入同一上下文。
