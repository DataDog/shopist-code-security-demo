# Code Security Demo

Intentionally vulnerable code samples across 7 languages and 14 rule types for demonstrating Datadog Code Security (SAST) capabilities.

> ⚠️ **WARNING**: This code is intentionally insecure and exists solely for security tooling demos. Never use these patterns in production.

## Rule Types & Instance Counts

| Rule Type                | Python | JavaScript | TypeScript | Go | Ruby | .NET (C#) | Java | **Total** |
|--------------------------|--------|------------|------------|----|------|-----------|------|-----------|
| SQL Injection            | 9      | 9          | —          | 9  | 9    | 9         | 9    | **54**    |
| Path Traversal           | 9      | 9          | —          | 9  | 9    | 9         | 9    | **54**    |
| Command Injection        | 9      | 9          | —          | 9  | 9    | 9         | 9    | **54**    |
| Hardcoded Secrets        | 9      | 9          | 9          | —  | 9    | 9         | 9    | **54**    |
| Weak Cryptography        | 9      | 9          | 9          | —  | 9    | 9         | 9    | **54**    |
| Insecure Deserialization | 6      | 6          | 6          | —  | 6    | 6         | 6    | **36**    |
| SSRF                     | 6      | 6          | 6          | —  | 6    | 6         | 6    | **36**    |
| XSS / Template Injection | 6      | 6          | 6          | —  | 6    | 6         | 6    | **36**    |
| Open Redirect            | 6      | 6          | 6          | —  | 6    | 6         | 6    | **36**    |
| LDAP Injection           | 3      | 3          | 3          | —  | 3    | 3         | 3    | **18**    |
| XXE                      | 3      | 3          | 3          | —  | 3    | 3         | 3    | **18**    |
| Code Injection           | 3      | 3          | 3          | —  | 3    | 3         | 3    | **18**    |
| Insecure Cookie          | 3      | 3          | 3          | —  | 3    | 3         | 3    | **18**    |
| Header Injection         | 3      | —          | —          | —  | —    | —         | —    | **3**     |
| **Total**                | **84** | **81**     | **54**     | **27** | **81** | **81** | **81** | **489** |

## Structure

```
shopist-code-security-demo/
├── python/
│   ├── sql_injection/              (user_queries, product_queries, order_queries)
│   ├── path_traversal/             (file_download, static_files, file_upload)
│   ├── command_injection/          (file_operations, system_utils, report_generator)
│   ├── hardcoded_secrets/          (payment_config, auth_config, third_party_keys)
│   ├── weak_cryptography/          (password_hashing, encryption, random_tokens)
│   ├── insecure_deserialization/   (cart_persistence, session_handling)
│   ├── ssrf/                       (payment_webhooks, product_enrichment)
│   ├── xss/                        (product_reviews, template_injection)
│   ├── open_redirect/              (checkout_flow, account_management)
│   ├── ldap_injection/             (user_authentication)
│   ├── xxe/                        (product_import)
│   ├── code_injection/             (eval_usage)
│   ├── insecure_cookie/            (session_config)
│   └── header_injection/           (email_notifications)
├── javascript/                     (same structure, no header_injection)
├── typescript/                     (hardcoded_secrets through insecure_cookie)
├── go/                             (sql_injection, path_traversal, command_injection)
├── ruby/                           (same structure as javascript)
├── dotnet/                         (same structure as javascript)
└── java/                           (same structure as javascript)
```

## Vulnerability Patterns by Rule Type

### SQL Injection
- String concatenation into `execute()` / `query()` / `executeQuery()`
- f-string / template literal interpolation in SQL
- `%`-format / `String.format()` / `fmt.Sprintf()` in SQL
- Unparameterized `ORDER BY` clause injection

### Path Traversal
- `open()` / `File.read` / `fs.readFile` with user-controlled filename (no canonicalization)
- `send_file` / `res.sendFile` / `PhysicalFile` / `http.ServeFile` with user-controlled path
- Directory listing via `os.listdir` / `Directory.GetFiles` / `Files.list` with user-controlled dir
- Arbitrary file write: saving uploaded files to user-specified destination path
- Zip slip: extracting archives to user-controlled directory without entry path validation

### Command Injection
- `os.system()` / `exec()` / `Runtime.exec()` with user-controlled input
- `subprocess` / `ProcessBuilder` with `shell=True` or `sh -c`
- Backtick execution / `os.popen()` with string interpolation

### Hardcoded Secrets
- API keys and payment credentials (`sk_live_`, SendGrid, Twilio, Google Maps)
- Cloud provider credentials (AWS access key + secret, S3 connection config)
- Auth secrets: JWT signing key, SMTP passwords, hardcoded admin credentials

### Weak Cryptography
- Broken hash algorithms: MD5 / SHA1 for password storage
- Broken ciphers: DES, RC4, AES-ECB (no IV, reveals plaintext patterns)
- Insecure randomness: `Math.random()` / `java.util.Random` / `random.random()` for tokens, CSRF values, confirmation codes

### Insecure Deserialization
- `pickle.loads` / `Marshal.load` / `ObjectInputStream.readObject` on user-controlled input (RCE)
- `yaml.load()` without safe loader on user input
- `node-serialize` unserialize on cookie data (IIFE RCE)

### SSRF
- `requests.get` / `HttpClient` / `Net::HTTP` on user-controlled URLs (webhooks, image import, carrier tracking)
- `urllib.request.urlopen` / `URL.openStream()` / `open-uri` on user-supplied source URLs
- User-controlled API base URL string-concatenated before fetch

### XSS / Template Injection
- Reflected XSS: user input rendered directly into HTML response without escaping
- Stored XSS: DB content rendered with `raw()` / `innerHTML` / `Response.Write` without sanitization
- SSTI: user-controlled template string passed to Jinja2 `render_template_string`, Freemarker, Velocity, ERB, EJS, Pug, Handlebars

### Open Redirect
- Unvalidated `next` / `return_url` / `redirect_to` parameters after login or checkout
- `Referer` header used directly as redirect target on logout
- OAuth `state` parameter used as post-auth redirect without validation

### LDAP Injection
- String concatenation / interpolation in LDAP search filters for authentication
- Unsanitized input in employee lookup and group membership filters via `DirContext` / `DirectorySearcher` / `ldapjs` / `Net::LDAP`

### XXE
- `DocumentBuilderFactory` / `XmlDocument` / `Nokogiri::XML` with default settings (external entity expansion enabled)
- `SAXParserFactory` / `XMLInputFactory` with DTD processing / external entity support
- `libxmljs` / `fast-xml-parser` with `processEntities: true` / `dtdload: true`

### Code Injection
- `eval()` / `exec()` on user-supplied discount formulas or filter expressions
- `ScriptEngine.eval()` / `CSharpScript.EvaluateAsync` / `GroovyShell.evaluate()` on user input
- `vm.runInNewContext()` / `new Function(userCode)()` on user-controlled strings

### Insecure Cookie
- Session cookies missing `Secure` flag (transmitted over HTTP)
- Auth cookies missing `HttpOnly` flag (accessible via JavaScript)
- Cookies set with no `SameSite` attribute and overly broad domain scope

### Header Injection
- User input inserted unsanitized into HTTP response headers
- Email header injection via newline characters in SMTP `To` / `Subject` fields
- `Location` header constructed by concatenating unvalidated user input
