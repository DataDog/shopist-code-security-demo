# Code Security Demo

Intentionally vulnerable code samples across 10 languages and 14 rule types for demonstrating Datadog Code Security capabilities. Not all supported languages are represented — see the [full list of supported languages and rules](https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/?categories=Security).

> ⚠️ **WARNING**: This code is intentionally insecure and exists solely for security tooling demos. Never use these patterns in production.

## Rule Types & Instance Counts

| Rule Type                | Python | JS | TS | Go | Ruby | .NET | Java | Kotlin | PHP | Swift | **Total** |
|--------------------------|--------|----|----|-----|------|------|------|--------|-----|-------|-----------|
| SQL Injection            | 9      | 9  | —  | 9  | 9    | 9    | 9    | 9      | 9   | 9     | **81**    |
| Path Traversal           | 9      | 9  | —  | 9  | 9    | 9    | 9    | 9      | 9   | 9     | **81**    |
| Command Injection        | 9      | 9  | —  | 9  | 9    | 9    | 9    | 9      | 9   | 9     | **81**    |
| Hardcoded Secrets        | 9      | 9  | 9  | 9  | 9    | 9    | 9    | 9      | 9   | 9     | **90**    |
| Weak Cryptography        | 9      | 9  | 9  | 9  | 9    | 9    | 9    | 9      | 9   | 9     | **90**    |
| SSRF                     | 6      | 6  | 6  | 6  | 6    | 6    | 6    | 6      | 6   | 6     | **60**    |
| Open Redirect            | 6      | 6  | 6  | 6  | 6    | 6    | 6    | 6      | 6   | 6     | **60**    |
| Insecure Deserialization | 6      | 6  | 6  | —  | 6    | 6    | 6    | 6      | 6   | 6     | **54**    |
| XSS / Template Injection | 6      | 6  | 6  | —  | 6    | 6    | 6    | 6      | 6   | —     | **48**    |
| Insecure Cookie          | 3      | 3  | 3  | 3  | 3    | 3    | 3    | 3      | 3   | 3     | **30**    |
| XXE                      | 3      | 3  | 3  | 3  | 3    | 3    | 3    | 3      | 3   | —     | **27**    |
| LDAP Injection           | 3      | 3  | 3  | —  | 3    | 3    | 3    | 3      | 3   | —     | **24**    |
| Code Injection           | 3      | 3  | 3  | —  | 3    | 3    | 3    | 3      | 3   | —     | **24**    |
| Header Injection         | 3      | —  | —  | —  | —    | —    | —    | —      | —   | —     | **3**     |
| **Total**                | **84** | **81** | **54** | **63** | **81** | **81** | **81** | **81** | **81** | **66** | **753** |

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
├── typescript/                     (hardcoded_secrets through insecure_cookie, no sql/path/cmd)
├── go/                             (sql_injection, path_traversal, command_injection,
│                                    hardcoded_secrets, weak_cryptography, ssrf,
│                                    open_redirect, xxe, insecure_cookie)
├── ruby/                           (same structure as javascript)
├── dotnet/                         (same structure as javascript)
├── java/                           (same structure as javascript)
├── kotlin/                         (same structure as javascript)
├── php/                            (same structure as javascript)
└── swift/                          (sql_injection, path_traversal, command_injection,
                                     hardcoded_secrets, weak_cryptography, ssrf,
                                     open_redirect, insecure_deserialization, insecure_cookie)
```

## Vulnerability Patterns by Rule Type

### SQL Injection
- String concatenation into `execute()` / `query()` / `executeQuery()`
- f-string / template literal / Kotlin string template interpolation in SQL
- `%`-format / `String.format()` / `fmt.Sprintf()` / `sprintf()` in SQL
- Unparameterized `ORDER BY` clause injection

### Path Traversal
- `open()` / `File.read` / `fs.readFile` / `file_get_contents` with user-controlled filename (no canonicalization)
- `send_file` / `res.sendFile` / `PhysicalFile` / `http.ServeFile` with user-controlled path
- Directory listing via `os.listdir` / `Directory.GetFiles` / `Files.list` with user-controlled dir
- Arbitrary file write: saving uploaded files to user-specified destination path
- Zip slip: extracting archives to user-controlled directory without entry path validation

### Command Injection
- `os.system()` / `exec()` / `Runtime.exec()` / `system()` with user-controlled input
- `subprocess` / `ProcessBuilder` / `Process` with `shell=True` or `sh -c`
- Backtick execution / `os.popen()` / `shell_exec()` / `passthru()` with string interpolation

### Hardcoded Secrets
- Payment API keys (`sk_live_` Stripe, SendGrid, Twilio, Google Maps)
- Cloud provider credentials (AWS `AKIA` access key + secret, S3 config)
- Auth secrets: JWT signing key, SMTP passwords, hardcoded admin credentials

### Weak Cryptography
- Broken hash algorithms: MD5 / SHA1 for password storage (`Digest::MD5`, `MessageDigest.getInstance("MD5")`, `crypto.createHash('md5')`)
- Broken ciphers: DES, RC4, AES-ECB (no IV, reveals plaintext patterns)
- Insecure randomness: `Math.random()` / `java.util.Random` / `random.random()` / `rand()` / `arc4random()` for security tokens, CSRF values, confirmation codes

### Insecure Deserialization
- `pickle.loads` / `Marshal.load` / `ObjectInputStream.readObject` / `unserialize()` on user-controlled input (RCE)
- `yaml.load()` / `Yaml().load()` without safe loader on user input
- `node-serialize` / `NSKeyedUnarchiver.unarchiveObject` on untrusted data

### SSRF
- `requests.get` / `HttpClient` / `Net::HTTP` / `http.Get` / `file_get_contents` / `URLSession` on user-controlled URLs (webhooks, image import, carrier tracking)
- User-controlled API base URL string-concatenated before fetch
- `urllib.request.urlopen` / `URL.openStream()` / `open-uri` / `curl_exec` on user-supplied source URLs

### XSS / Template Injection
- Reflected XSS: user input rendered directly into HTML response without escaping
- Stored XSS: DB content rendered with `raw()` / `innerHTML` / `Response.Write` / `echo` without sanitization
- SSTI: user-controlled template string passed to Jinja2 `render_template_string`, Freemarker, Velocity, ERB, EJS, Pug, Handlebars, Twig, Smarty

### Open Redirect
- Unvalidated `next` / `return_url` / `redirect_to` parameters after login or checkout
- `Referer` / `HTTP_REFERER` header used directly as redirect target on logout
- OAuth `state` parameter used as post-auth redirect without validation

### LDAP Injection
- String concatenation / interpolation in LDAP search filters for authentication
- Unsanitized input in employee lookup and group membership filters via `DirContext` / `DirectorySearcher` / `ldapjs` / `Net::LDAP` / `ldap_search`

### XXE
- `DocumentBuilderFactory` / `XmlDocument` / `Nokogiri::XML` / `DOMDocument::loadXML` / `xml.NewDecoder` with default settings (external entity expansion enabled)
- `SAXParserFactory` / `XMLInputFactory` with DTD processing / external entity support
- `libxmljs` / `fast-xml-parser` / `SimpleXMLElement` with `LIBXML_NOENT` / entity loading enabled

### Code Injection
- `eval()` / `exec()` / `eval()` (PHP) on user-supplied discount formulas or filter expressions
- `ScriptEngine.eval()` / `CSharpScript.EvaluateAsync` / `GroovyShell.evaluate()` on user input
- `vm.runInNewContext()` / `new Function(userCode)()` / `preg_replace` with `e` modifier on user-controlled strings

### Insecure Cookie
- Session cookies missing `Secure` flag (transmitted over HTTP)
- Auth cookies missing `HttpOnly` flag (accessible via JavaScript / XSS)
- Cookies set with no `SameSite` attribute and overly broad domain scope

### Header Injection
- User input inserted unsanitized into HTTP response headers
- Email header injection via newline characters in SMTP `To` / `Subject` fields
- `Location` header constructed by concatenating unvalidated user input
