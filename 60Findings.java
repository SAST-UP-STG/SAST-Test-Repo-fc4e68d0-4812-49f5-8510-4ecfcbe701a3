@Controller
@Slf4j
@AssignmentHints({"crypto-hashing.hints.1", "crypto-hashing.hints.2"})
public class FileServer {

  @Value("${webwolf.fileserver.location}")
  private String fileLocation;

  @Value("${server.address}")
  private String server;

  @Value("${server.port}")
  private int port;

  @RequestMapping(
      path = "/file-server-location",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getFileLocation() {
    return fileLocation;
  }

  @PostMapping(value = "/fileupload")
  public ModelAndView importFile(@RequestParam("file") MultipartFile myFile) throws IOException {
    var user = (WebGoatUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    var destinationDir = new File(fileLocation, user.getUsername());
    destinationDir.mkdirs();
    myFile.transferTo(new File(destinationDir, myFile.getOriginalFilename()));
    log.debug("File saved to {}", new File(destinationDir, myFile.getOriginalFilename()));

    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", "File uploaded successful"));
  }

  @AllArgsConstructor
  @Getter
  private class UploadedFile {
    private final String name;
    private final String size;
    private final String link;
  }

  @GetMapping(value = "/files")
  public ModelAndView getFiles(HttpServletRequest request) {
    WebGoatUser user =
        (WebGoatUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String username = user.getUsername();
    File destinationDir = new File(fileLocation, username);

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.setViewName("files");
    File changeIndicatorFile = new File(destinationDir, user.getUsername() + "_changed");
    if (changeIndicatorFile.exists()) {
      modelAndView.addObject("uploadSuccess", request.getParameter("uploadSuccess"));
    }
    changeIndicatorFile.delete();

    var uploadedFiles = new ArrayList<>();
    File[] files = destinationDir.listFiles(File::isFile);
    if (files != null) {
      for (File file : files) {
        String size = FileUtils.byteCountToDisplaySize(file.length());
        String link = String.format("files/%s/%s", username, file.getName());
        uploadedFiles.add(new UploadedFile(file.getName(), size, link));
      }
    }

    modelAndView.addObject("files", uploadedFiles);
    modelAndView.addObject("webwolf_url", "http://" + server + ":" + port);
    return modelAndView;
  }

public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD1 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD2 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD3 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD4 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD5 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD6 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD7 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD8 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD9 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD0 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD11 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD22 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD33 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD44 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD55 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD66 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD77 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD88 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD99 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD00 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD12 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD23 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD24 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD25 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD26 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD27 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD34 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD35 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD36 = "bm5nhSkxCXZkKRy4";
public static final String PASSWORD37 = "bm5nhSkxCXZkKRy4";
  private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD1 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD2 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD3 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD4 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD5 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD6 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD7 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD8 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD9 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD0 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD11 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD22 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD33 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD44 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD55 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD66 = "bm5n3SkxCX4kKRy4";
private static final String JWT_PASSWORD77 = "bm5n3SkxCX4kKRy4";


  private static final List<String> validRefreshTokens = new ArrayList<>();

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("admin", "false");
    claims.put("user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();

    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    validRefreshTokens.add(refreshToken);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping(
      value = "/JWT/refresh/login1",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow11(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens11(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens11(String user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("admin", "false");
    claims.put("user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD11)
            .compact();
            
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    validRefreshTokens.add(refreshToken);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping(
      value = "/JWT/refresh/login22",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow11(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens22(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens22(String user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("admin", "false");
    claims.put("user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD22)
            .compact();
            
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    validRefreshTokens.add(refreshToken);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
      Claims claims = (Claims) jwt.getBody();
      String user = (String) claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken;
    try {
      Jwt<Header, Claims> jwt =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
      user = (String) jwt.getBody().get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (ExpiredJwtException e) {
      user = (String) e.getClaims().get("user");
      refreshToken = (String) json.get("refresh_token");
    }

    if (user == null || refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else if (validRefreshTokens.contains(refreshToken)) {
      validRefreshTokens.remove(refreshToken);
      return ok(createNewTokens(user));
    } else {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};

  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getMd5(HttpServletRequest request) throws NoSuchAlgorithmException {

    String md5Hash = (String) request.getSession().getAttribute("md5Hash");
    if (md5Hash == null) {

      String secret = SECRETS[new Random().nextInt(SECRETS.length)];

      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(secret.getBytes());
      byte[] digest = md.digest();
      md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
      request.getSession().setAttribute("md5Hash", md5Hash);
      request.getSession().setAttribute("md5Secret", secret);
    }
    return md5Hash;
  }

  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) throws NoSuchAlgorithmException {

    String sha256 = (String) request.getSession().getAttribute("sha256");
    if (sha256 == null) {
      String secret = SECRETS[new Random().nextInt(SECRETS.length)];
      sha256 = getHash(secret, "SHA-256");
      request.getSession().setAttribute("sha256Hash", sha256);
      request.getSession().setAttribute("sha256Secret", secret);
    }
    return sha256;
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {

    String md5Secret = (String) request.getSession().getAttribute("md5Secret");
    String sha256Secret = (String) request.getSession().getAttribute("sha256Secret");

    if (answer_pwd1 != null && answer_pwd2 != null) {
      if (answer_pwd1.equals(md5Secret) && answer_pwd2.equals(sha256Secret)) {
        return success(this).feedback("crypto-hashing.success").build();
      } else if (answer_pwd1.equals(md5Secret) || answer_pwd2.equals(sha256Secret)) {
        return failed(this).feedback("crypto-hashing.oneok").build();
      }
    }
    return failed(this).feedback("crypto-hashing.empty").build();
  }

  public static String getHash(String secret, String algorithm) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(secret.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest).toUpperCase();
  }

private final LessonDataSource dataSource;

  public SqlInjectionLesson10(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }


  @PostMapping("/SqlInjection/attack10")
  @ResponseBody
  public AttackResult completed(@RequestParam String action_string) {
    return injectableQueryAvailability(action_string);
  }

  protected AttackResult injectableQueryAvailability(String action) {
    StringBuilder output = new StringBuilder();
    String query = "SELECT * FROM access_log WHERE action LIKE '%" + action + "%'";

    try (Connection connection = dataSource.getConnection()) {
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results.getStatement() != null) {
          results.first();
          output.append(SqlInjectionLesson8.generateTable(results));
          return failed(this)
              .feedback("sql-injection.10.entries")
              .output(output.toString())
              .build();
        } else {
          if (tableExists(connection)) {
            return failed(this)
                .feedback("sql-injection.10.entries")
                .output(output.toString())
                .build();
          } else {
            return success(this).feedback("sql-injection.10.success").build();
          }
        }
      } catch (SQLException e) {
        if (tableExists(connection)) {
          return failed(this)
              .output(
                  "<span class='feedback-negative'>"
                      + e.getMessage()
                      + "</span><br>"
                      + output.toString())
              .build();
        } else {
          return success(this).feedback("sql-injection.10.success").build();
        }
      }

    } catch (Exception e) {
      return failed(this)
          .output("<span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }

  private boolean tableExists(Connection connection) {
    try {
      Statement stmt =
          connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
      ResultSet results = stmt.executeQuery("SELECT * FROM access_log");
      int cols = results.getMetaData().getColumnCount();
      return (cols > 0);
    } catch (SQLException e) {
      String errorMsg = e.getMessage();
      if (errorMsg.contains("object not found: ACCESS_LOG")) {
        return false;
      } else {
        System.err.println(e.getMessage());
        return false;
      }
    }
  }

  @Autowired UserSessionData userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @RequestMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"},
      method = RequestMethod.POST)
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    String host = (req.getHeader("host") == null) ? "NULL" : req.getHeader("host");
    String referer = (req.getHeader("referer") == null) ? "NULL" : req.getHeader("referer");
    String[] refererArr = referer.split("/");

    if (referer.equals("NULL")) {
      if ("true".equals(req.getParameter("csrf"))) {
        Random random = new Random();
        userSessionData.setValue("csrf-get-success", random.nextInt(65536));
        response.put("success", true);
        response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
        response.put("flag", userSessionData.getValue("csrf-get-success"));
      } else {
        Random random = new Random();
        userSessionData.setValue("csrf-get-success", random.nextInt(65536));
        response.put("success", true);
        response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
        response.put("flag", userSessionData.getValue("csrf-get-success"));
      }
    } else if (refererArr[2].equals(host)) {
      response.put("success", false);
      response.put("message", "Appears the request came from the original host");
      response.put("flag", null);
    } else {
      Random random = new Random();
      userSessionData.setValue("csrf-get-success", random.nextInt(65536));
      response.put("success", true);
      response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
      response.put("flag", userSessionData.getValue("csrf-get-success"));
    }

    return response;
  }

  @Test
  public void runTests() {
    startLesson("Cryptography");

    checkAssignment2();
    checkAssignment3();

    // Assignment 4
    try {
      checkAssignment4();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      fail();
    }

    try {
      checkAssignmentSigning();
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
    
    checkAssignmentDefaults();

    checkResults("/crypto");

  }

  private void checkAssignment2() {

    String basicEncoding = RestAssured.given().when().relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie()).get(url("/crypto/encoding/basic")).then().extract()
        .asString();
    basicEncoding = basicEncoding.substring("Authorization: Basic ".length());
    String decodedString = new String(Base64.getDecoder().decode(basicEncoding.getBytes()));
    String answer_user = decodedString.split(":")[0];
    String answer_pwd = decodedString.split(":")[1];
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_user", answer_user);
    params.put("answer_pwd", answer_pwd);
    checkAssignment(url("/crypto/encoding/basic-auth"), params, true);
  }

  private void checkAssignment3() {
    String answer_1 = "databasepassword";
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    checkAssignment(url("/crypto/encoding/xor"), params, true);
  }

  private void checkAssignment4() throws NoSuchAlgorithmException {

    String md5Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/md5")).then().extract().asString();

    String sha256Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/sha256")).then().extract().asString();

    String answer_1 = "unknown";
    String answer_2 = "unknown";
    for (String secret : HashingAssignment.SECRETS) {
      if (md5Hash.equals(HashingAssignment.getHash(secret, "MD5"))) {
        answer_1 = secret;
      }
      if (sha256Hash.equals(HashingAssignment.getHash(secret, "SHA-256"))) {
        answer_2 = secret;
      }
    }

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    params.put("answer_pwd2", answer_2);
    checkAssignment(url("/WebGoat/crypto/hashing"), params, true);
  }

  private void checkAssignmentSigning() throws NoSuchAlgorithmException, InvalidKeySpecException {
      
      String privatePEM = RestAssured.given()
              .when()
              .relaxedHTTPSValidation()
              .cookie("JSESSIONID", getWebGoatCookie())
              .get(url("/crypto/signing/getprivate"))
              .then()
        .extract().asString();
    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(privatePEM);

    RSAPrivateKey privk = (RSAPrivateKey) privateKey;
    String modulus = DatatypeConverter.printHexBinary(privk.getModulus().toByteArray());
      String signature = CryptoUtil.signMessage(modulus, privateKey);
        Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("modulus", modulus);
        params.put("signature", signature);
        checkAssignment(url("/crypto/signing/verify"), params, true);
    }
  
  private void checkAssignmentDefaults() {
      
      String text = new String(Base64.getDecoder().decode("TGVhdmluZyBwYXNzd29yZHMgaW4gZG9ja2VyIGltYWdlcyBpcyBub3Qgc28gc2VjdXJl".getBytes(Charset.forName("UTF-8"))));

    Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("secretText", text);
        params.put("secretFileName", "default_secret");
        checkAssignment(url("/crypto/secure/defaults"), params, true);
    }

    public static String getBasicAuth(String username, String password) {
    return Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    String username = request.getUserPrincipal().getName();
    if (basicAuth == null) {
      String password =
          HashingAssignment.SECRETS[new Random().nextInt(HashingAssignment.SECRETS.length)];
      basicAuth = getBasicAuth(username, password);
      request.getSession().setAttribute("basicAuth", basicAuth);
    }
    return "Authorization: Basic ".concat(basicAuth);
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    if (basicAuth != null
        && answer_user != null
        && answer_pwd != null
        && basicAuth.equals(getBasicAuth(answer_user, answer_pwd))) {
      return success(this).feedback("crypto-encoding.success").build();
    } else {
      return failed(this).feedback("crypto-encoding.empty").build();
    }
  }

  public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};

  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getMd5(HttpServletRequest request) throws NoSuchAlgorithmException {

    String md5Hash = (String) request.getSession().getAttribute("md5Hash");
    if (md5Hash == null) {

      String secret = SECRETS[new Random().nextInt(SECRETS.length)];

      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(secret.getBytes());
      byte[] digest = md.digest();
      md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
      request.getSession().setAttribute("md5Hash", md5Hash);
      request.getSession().setAttribute("md5Secret", secret);
    }
    return md5Hash;
  }

  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) throws NoSuchAlgorithmException {

    String sha256 = (String) request.getSession().getAttribute("sha256");
    if (sha256 == null) {
      String secret = SECRETS[new Random().nextInt(SECRETS.length)];
      sha256 = getHash(secret, "SHA-256");
      request.getSession().setAttribute("sha256Hash", sha256);
      request.getSession().setAttribute("sha256Secret", secret);
    }
    return sha256;
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {

    String md5Secret = (String) request.getSession().getAttribute("md5Secret");
    String sha256Secret = (String) request.getSession().getAttribute("sha256Secret");

    if (answer_pwd1 != null && answer_pwd2 != null) {
      if (answer_pwd1.equals(md5Secret) && answer_pwd2.equals(sha256Secret)) {
        return success(this).feedback("crypto-hashing.success").build();
      } else if (answer_pwd1.equals(md5Secret) || answer_pwd2.equals(sha256Secret)) {
        return failed(this).feedback("crypto-hashing.oneok").build();
      }
    }
    return failed(this).feedback("crypto-hashing.empty").build();
  }

  public static String getHash(String secret, String algorithm) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(secret.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest).toUpperCase();
  }

  public static final String JWT_PASSWORD = TextCodec.BASE64.encode("victory");
  private static String validUsers = "TomJerrySylvester";

  private static int totalVotes = 38929;
  private Map<String, Vote> votes = new HashMap<>();

  @PostConstruct
  public void initVotes() {
    votes.put(
        "Admin lost password",
        new Vote(
            "Admin lost password",
            "In this challenge you will need to help the admin and find the password in order to"
                + " login",
            "challenge1-small.png",
            "challenge1.png",
            36000,
            totalVotes));
    votes.put(
        "Vote for your favourite",
        new Vote(
            "Vote for your favourite",
            "In this challenge ...",
            "challenge5-small.png",
            "challenge5.png",
            30000,
            totalVotes));
    votes.put(
        "Get it for free",
        new Vote(
            "Get it for free",
            "The objective for this challenge is to buy a Samsung phone for free.",
            "challenge2-small.png",
            "challenge2.png",
            20000,
            totalVotes));
    votes.put(
        "Photo comments",
        new Vote(
            "Photo comments",
            "n this challenge you can comment on the photo you will need to find the flag"
                + " somewhere.",
            "challenge3-small.png",
            "challenge3.png",
            10000,
            totalVotes));
  }

  @GetMapping("/JWT/votings/login")
  public void login(@RequestParam("user") String user, HttpServletResponse response) {
    if (validUsers.contains(user)) {
      Claims claims = Jwts.claims().setIssuedAt(Date.from(Instant.now().plus(Duration.ofDays(10))));
      claims.put("admin", "false");
      claims.put("user", user);
      String token =
          Jwts.builder()
              .setClaims(claims)
              .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
              .compact();
      Cookie cookie = new Cookie("access_token", token);
      response.addCookie(cookie);
      response.setStatus(HttpStatus.OK.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    } else {
      Cookie cookie = new Cookie("access_token", "");
      response.addCookie(cookie);
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
  }

  @GetMapping("/JWT/votings")
  @ResponseBody
  public MappingJacksonValue getVotes(
      @CookieValue(value = "access_token", required = false) String accessToken) {
    MappingJacksonValue value =
        new MappingJacksonValue(
            votes.values().stream()
                .sorted(comparingLong(Vote::getAverage).reversed())
                .collect(toList()));
    if (StringUtils.isEmpty(accessToken)) {
      value.setSerializationView(Views.GuestView.class);
    } else {
      try {
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Claims claims = (Claims) jwt.getBody();
        String user = (String) claims.get("user");
        if ("Guest".equals(user) || !validUsers.contains(user)) {
          value.setSerializationView(Views.GuestView.class);
        } else {
          value.setSerializationView(Views.UserView.class);
        }
      } catch (JwtException e) {
        value.setSerializationView(Views.GuestView.class);
      }
    }
    return value;
  }

  @PostMapping(value = "/JWT/votings/{title}")
  @ResponseBody
  @ResponseStatus(HttpStatus.ACCEPTED)
  public ResponseEntity<?> vote(
      @PathVariable String title,
      @CookieValue(value = "access_token", required = false) String accessToken) {
    if (StringUtils.isEmpty(accessToken)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else {
      try {
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Claims claims = (Claims) jwt.getBody();
        String user = (String) claims.get("user");
        if (!validUsers.contains(user)) {
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } else {
          ofNullable(votes.get(title)).ifPresent(v -> v.incrementNumberOfVotes(totalVotes));
          return ResponseEntity.accepted().build();
        }
      } catch (JwtException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      }
    }
  }

  @PostMapping("/JWT/votings")
  @ResponseBody
  public AttackResult resetVotes(
      @CookieValue(value = "access_token", required = false) String accessToken) {
    if (StringUtils.isEmpty(accessToken)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
        Claims claims = (Claims) jwt.getBody();
        boolean isAdmin = Boolean.valueOf(String.valueOf(claims.get("admin")));
        if (!isAdmin) {
          return failed(this).feedback("jwt-only-admin").build();
        } else {
          votes.values().forEach(vote -> vote.reset());
          return success(this).build();
        }
      } catch (JwtException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }
}

class BenchmarkTest00001 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00001", "FileName");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00001.html");
        rd.include(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        javax.servlet.http.Cookie[] theCookies = request.getCookies();

        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00001")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileInputStream fis = null;

        try {
            fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
            fis = new java.io.FileInputStream(new java.io.File(fileName));
            byte[] b = new byte[1000];
            int size = fis.read(b);
            response.getWriter()
                    .println(
                            "The beginning of file: '"
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName)
                                    + "' is:\n\n"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(b, 0, size)));
        } catch (Exception e) {
            System.out.println("Couldn't open FileInputStream on file: '" + fileName + "'");
            response.getWriter()
                    .println(
                            "Problem getting FileInputStream: "
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(e.getMessage()));
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                    fis = null;
                } catch (Exception e) {
                    // we tried...
                }
            }
        }
    }
}

class BenchmarkTest00002 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00002", "FileName");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00002.html");
        rd.include(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        javax.servlet.http.Cookie[] theCookies = request.getCookies();

        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00002")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

            fos = new java.io.FileOutputStream(fileName, false);
            response.getWriter()
                    .println(
                            "Now ready to write to file: "
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

        } catch (Exception e) {
            System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
            //      System.out.println("File exception caught and swallowed: " + e.getMessage());
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                    fos = null;
                } catch (Exception e) {
                    // we tried...
                }
            }
        }
    }
}


class BenchmarkTest00003 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00003", "someSecret");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/hash-00/BenchmarkTest00003.html");
        rd.include(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        javax.servlet.http.Cookie[] theCookies = request.getCookies();

        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00003")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        try {
            java.util.Properties benchmarkprops = new java.util.Properties();
            benchmarkprops.load(
                    this.getClass().getClassLoader().getResourceAsStream("benchmark.properties"));
            String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
            java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
            byte[] input = {(byte) '?'};
            Object inputParam = param;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }
            md.update(input);

            byte[] result = md.digest();
            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "hash_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\n");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' hashed and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException e) {
            System.out.println("Problem executing hash - TestCase");
            throw new ServletException(e);
        }

        response.getWriter()
                .println(
                        "Hash Test java.security.MessageDigest.getInstance(java.lang.String) executed");
    }
}


class BenchmarkTest00004 extends HttpServlet {
private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00004", "color");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/trustbound-00/BenchmarkTest00004.html");
        rd.include(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        javax.servlet.http.Cookie[] theCookies = request.getCookies();

        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00004")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        // javax.servlet.http.HttpSession.setAttribute(java.lang.String^,java.lang.Object)
        request.getSession().setAttribute(param, "10340");

        response.getWriter()
                .println(
                        "Item: '"
                                + org.owasp.benchmark.helpers.Utils.encodeForHTML(param)
                                + "' with value: '10340' saved in session.");
    }
}

class BenchmarkTest00005 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00005") != null) {
            param = request.getHeader("BenchmarkTest00005");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        // Code based on example from:
        // http://examples.javacodegeeks.com/core-java/crypto/encrypt-decrypt-file-stream-with-des/
        // 8-byte initialization vector
        //    byte[] iv = {
        //      (byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
        //      (byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3033
        //    };
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] iv = random.generateSeed(8); // DES requires 8 byte keys

        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");

            // Prepare the cipher to encrypt
            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();
            java.security.spec.AlgorithmParameterSpec paramSpec =
                    new javax.crypto.spec.IvParameterSpec(iv);
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);

            // encrypt and store the results
            byte[] input = {(byte) '?'};
            Object inputParam = param;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }
            byte[] result = c.doFinal(input);

            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "secret_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\n");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value: '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' encrypted and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException
                | javax.crypto.NoSuchPaddingException
                | javax.crypto.IllegalBlockSizeException
                | javax.crypto.BadPaddingException
                | java.security.InvalidKeyException
                | java.security.InvalidAlgorithmParameterException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        }
    }
}


class BenchmarkTest00006 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00006") != null) {
            param = request.getHeader("BenchmarkTest00006");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        java.util.List<String> argList = new java.util.ArrayList<String>();

        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe");
            argList.add("/c");
        } else {
            argList.add("sh");
            argList.add("-c");
        }
        argList.add("echo " + param);

        ProcessBuilder pb = new ProcessBuilder();

        pb.command(argList);

        try {
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
            throw new ServletException(e);
        }
    }
}


class BenchmarkTest00007 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00007") != null) {
            param = request.getHeader("BenchmarkTest00007");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String cmd =
                org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                        this.getClass().getClassLoader());
        String[] args = {cmd};
        String[] argsEnv = {param};

        Runtime r = Runtime.getRuntime();

        try {
            Process p = r.exec(args, argsEnv);
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
}


class BenchmarkTest00008 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "{call " + param + "}";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            java.sql.ResultSet rs = statement.executeQuery();
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);

        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
                return;
            } else throw new ServletException(e);
        }
    }
}


class BenchmarkTest00009 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();

            if (org.owasp.benchmark.helpers.Utils.commonHeaders.contains(name)) {
                continue; // If standard header, move on to next one
            }

            java.util.Enumeration<String> values = request.getHeaders(name);
            if (values != null && values.hasMoreElements()) {
                param = name; // Grabs the name of the first non-standard header as the parameter
                // value
                break;
            }
        }
        // Note: We don't URL decode header names because people don't normally do that

        java.security.Provider[] provider = java.security.Security.getProviders();
        java.security.MessageDigest md;

        try {
            if (provider.length > 1) {

                md = java.security.MessageDigest.getInstance("sha-384", provider[0]);
            } else {
                md = java.security.MessageDigest.getInstance("sha-384", "SUN");
            }
            byte[] input = {(byte) '?'};
            Object inputParam = param;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }
            md.update(input);

            byte[] result = md.digest();
            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "hash_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\n");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' hashed and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException e) {
            System.out.println(
                    "Problem executing hash - TestCase java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider)");
            throw new ServletException(e);
        } catch (java.security.NoSuchProviderException e) {
            System.out.println(
                    "Problem executing hash - TestCase java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider)");
            throw new ServletException(e);
        }

        response.getWriter()
                .println(
                        "Hash Test java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider) executed");
    }
}


class BenchmarkTest00010 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();

            if (org.owasp.benchmark.helpers.Utils.commonHeaders.contains(name)) {
                continue; // If standard header, move on to next one
            }

            java.util.Enumeration<String> values = request.getHeaders(name);
            if (values != null && values.hasMoreElements()) {
                param = name; // Grabs the name of the first non-standard header as the parameter
                // value
                break;
            }
        }
        // Note: We don't URL decode header names because people don't normally do that

        try {
            int randNumber = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);
            String rememberMeKey = Integer.toString(randNumber);

            String user = "SafeInga";
            String fullClassName = this.getClass().getName();
            String testCaseNumber =
                    fullClassName.substring(
                            fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length());
            user += testCaseNumber;

            String cookieName = "rememberMe" + testCaseNumber;

            boolean foundUser = false;
            javax.servlet.http.Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (int i = 0; !foundUser && i < cookies.length; i++) {
                    javax.servlet.http.Cookie cookie = cookies[i];
                    if (cookieName.equals(cookie.getName())) {
                        if (cookie.getValue()
                                .equals(request.getSession().getAttribute(cookieName))) {
                            foundUser = true;
                        }
                    }
                }
            }

            if (foundUser) {
                response.getWriter().println("Welcome back: " + user + "<br/>");
            } else {
                javax.servlet.http.Cookie rememberMe =
                        new javax.servlet.http.Cookie(cookieName, rememberMeKey);
                rememberMe.setSecure(true);
                rememberMe.setHttpOnly(true);
                rememberMe.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
                // e.g., /benchmark/sql-01/BenchmarkTest01001
                request.getSession().setAttribute(cookieName, rememberMeKey);
                response.addCookie(rememberMe);
                response.getWriter()
                        .println(
                                user
                                        + " has been remembered with cookie: "
                                        + rememberMe.getName()
                                        + " whose value is: "
                                        + rememberMe.getValue()
                                        + "<br/>");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            System.out.println("Problem executing SecureRandom.nextInt(int) - TestCase");
            throw new ServletException(e);
        }
        response.getWriter()
                .println("Weak Randomness Test java.security.SecureRandom.nextInt(int) executed");
    }
}


class BenchmarkTest00011 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00011");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        java.io.File fileTarget = new java.io.File(param, "/Test.txt");
        response.getWriter()
                .println(
                        "Access to file: '"
                                + org.owasp
                                        .esapi
                                        .ESAPI
                                        .encoder()
                                        .encodeForHTML(fileTarget.toString())
                                + "' created.");
        if (fileTarget.exists()) {
            response.getWriter().println(" And file already exists.");
        } else {
            response.getWriter().println(" But file doesn't exist yet.");
        }
    }
}


class BenchmarkTest00012 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00012");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
        try {
            response.setContentType("text/html;charset=UTF-8");
            String base = "ou=users,ou=system";
            javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
            sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
            String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
            Object[] filters = new Object[] {"The streetz 4 Ms bar"};

            javax.naming.directory.DirContext ctx = ads.getDirContext();
            javax.naming.directory.InitialDirContext idc =
                    (javax.naming.directory.InitialDirContext) ctx;
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    idc.search(base, filter, filters, sc);
            while (results.hasMore()) {
                javax.naming.directory.SearchResult sr =
                        (javax.naming.directory.SearchResult) results.next();
                javax.naming.directory.Attributes attrs = sr.getAttributes();

                javax.naming.directory.Attribute attr = attrs.get("uid");
                javax.naming.directory.Attribute attr2 = attrs.get("street");
                if (attr != null) {
                    response.getWriter()
                            .println(
                                    "LDAP query results:<br>"
                                            + "Record found with name "
                                            + attr.get()
                                            + "<br>"
                                            + "Address: "
                                            + attr2.get()
                                            + "<br>");
                    // System.out.println("record found " + attr.get());
                    found = true;
                }
            }
            if (!found) {
                response.getWriter()
                        .println(
                                "LDAP query results: nothing found for query: "
                                        + org.owasp.esapi.ESAPI.encoder().encodeForHTML(filter));
            }
        } catch (javax.naming.NamingException e) {
            throw new ServletException(e);
        } finally {
            try {
                ads.closeDirContext();
            } catch (Exception e) {
                throw new ServletException(e);
            }
        }
    }
}


class BenchmarkTest00013 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("Referer");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        response.setHeader("X-XSS-Protection", "0");
        Object[] obj = {"a", "b"};
        response.getWriter().format(java.util.Locale.US, param, obj);
    }
}

class BenchmarkTest00014 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("Referer");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        response.setHeader("X-XSS-Protection", "0");
        Object[] obj = {"a", "b"};
        response.getWriter().format(param, obj);
    }
}


class BenchmarkTest00015 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00015");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        java.util.List<String> argList = new java.util.ArrayList<String>();

        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe");
            argList.add("/c");
        } else {
            argList.add("sh");
            argList.add("-c");
        }
        argList.add("echo " + param);

        ProcessBuilder pb = new ProcessBuilder();

        pb.command(argList);

        try {
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
            throw new ServletException(e);
        }
    }
}


class BenchmarkTest00016 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00016");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        byte[] input = new byte[1000];
        String str = "?";
        Object inputParam = param;
        if (inputParam instanceof String) str = ((String) inputParam);
        if (inputParam instanceof java.io.InputStream) {
            int i = ((java.io.InputStream) inputParam).read(input);
            if (i == -1) {
                response.getWriter()
                        .println(
                                "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                return;
            }
            str = new String(input, 0, i);
        }
        if ("".equals(str)) str = "No cookie value supplied";
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
        // e.g., /benchmark/sql-01/BenchmarkTest01001
        response.addCookie(cookie);

        response.getWriter()
                .println(
                        "Created cookie: 'SomeCookie': with value: '"
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
                                + "' and secure flag set to: true");
    }
}


class BenchmarkTest00017 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00017");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String cmd = "";
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
        }

        Runtime r = Runtime.getRuntime();

        try {
            Process p = r.exec(cmd + param);
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
}


class BenchmarkTest00018 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";

        try {
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            int count = statement.executeUpdate(sql);
            int count1 = statement.executeUpdate(sql);
            int count2 = statement.executeUpdate(sql);
            int count22 = statement.executeUpdate(sql);
            int count3 = statement.executeUpdate(sql);
            int count4 = statement.executeUpdate(sql);
            int count5 = statement.executeUpdate(sql);
            int count6 = statement.executeUpdate(sql);
            int count7 = statement.executeUpdate(sql);
            int count8 = statement.executeUpdate(sql);
            int count9 = statement.executeUpdate(sql);
            int count11 = statement.executeUpdate(sql);
            int count222 = statement.executeUpdate(sql);
            int count33 = statement.executeUpdate(sql);
            int count44 = statement.executeUpdate(sql);
            int count55 = statement.executeUpdate(sql);
            int count66 = statement.executeUpdate(sql);
            int count77 = statement.executeUpdate(sql);
            int count88 = statement.executeUpdate(sql);
            int count99 = statement.executeUpdate(sql);
            int count0 = statement.executeUpdate(sql);
            int count00 = statement.executeUpdate(sql);
            int count000 = statement.executeUpdate(sql);
            int asdf = statement.executeUpdate(sql);
            int sdgsdg = statement.executeUpdate(sql);
            int asdfsg = statement.executeUpdate(sql);
            int asdfsg = statement.executeUpdate(sql);
            int zxcv = statement.executeUpdate(sql);
            int xcvb = statement.executeUpdate(sql);
            int cvbn = statement.executeUpdate(sql);
            int cvbm = statement.executeUpdate(sql);
            int qwer = statement.executeUpdate(sql);
            int wert = statement.executeUpdate(sql);
            int ety = statement.executeUpdate(sql);
            int tryu = statement.executeUpdate(sql);
            int ujm = statement.executeUpdate(sql);
            int yhn = statement.executeUpdate(sql);
            int tbg = statement.executeUpdate(sql);
            int vrv = statement.executeUpdate(sql);
            int ec = statement.executeUpdate(sql);
            int uujn = statement.executeUpdate(sql);


            org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
                return;
            } else throw new ServletException(e);
        }
    }
}


class BenchmarkTest00019 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        java.io.InputStream param = request.getInputStream();

        try {
            java.util.Properties benchmarkprops = new java.util.Properties();
            benchmarkprops.load(
                    this.getClass().getClassLoader().getResourceAsStream("benchmark.properties"));
            String algorithm = benchmarkprops.getProperty("cryptoAlg1", "DESede/ECB/PKCS5Padding");
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(algorithm);

            // Prepare the cipher to encrypt
            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);

            // encrypt and store the results
            byte[] input = {(byte) '?'};
            Object inputParam = param;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }
            byte[] result = c.doFinal(input);

            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "secret_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\n");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value: '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' encrypted and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException
                | javax.crypto.NoSuchPaddingException
                | javax.crypto.IllegalBlockSizeException
                | javax.crypto.BadPaddingException
                | java.security.InvalidKeyException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        }
    }
}


class BenchmarkTest00020 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = request.getParameter("BenchmarkTest00020");
        if (param == null) param = "";

        // Code based on example from:
        // http://examples.javacodegeeks.com/core-java/crypto/encrypt-decrypt-file-stream-with-des/
        // 8-byte initialization vector
        //      byte[] iv = {
        //        (byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
        //        (byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3033
        //      };
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] iv = random.generateSeed(8); // DES requires 8 byte keys

        try {
            javax.crypto.Cipher c =
                    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");
            // Prepare the cipher to encrypt
            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();
            java.security.spec.AlgorithmParameterSpec paramSpec =
                    new javax.crypto.spec.IvParameterSpec(iv);
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);

            // encrypt and store the results
            byte[] input = {(byte) '?'};
            Object inputParam = param;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }
            byte[] result = c.doFinal(input);

            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "secret_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "\n");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value: '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' encrypted and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (java.security.NoSuchProviderException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (javax.crypto.NoSuchPaddingException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (javax.crypto.IllegalBlockSizeException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (javax.crypto.BadPaddingException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (java.security.InvalidKeyException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        } catch (java.security.InvalidAlgorithmParameterException e) {
            response.getWriter()
                    .println(
                            "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case");
            e.printStackTrace(response.getWriter());
            throw new ServletException(e);
        }
        response.getWriter()
                .println(
                        "Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");
    }
}



package org.owasp.webgoat;

import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.cryptography.CryptoUtil;
import org.owasp.webgoat.lessons.cryptography.HashingAssignment;

import io.restassured.RestAssured;

public class CryptoIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("Cryptography");

    checkAssignment2();
    checkAssignment3();

    // Assignment 4
    try {
      checkAssignment4();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      fail();
    }

    try {
      checkAssignmentSigning();
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
    
    checkAssignmentDefaults();

    checkResults("/crypto");

  }

  private void checkAssignment2() {

    String basicEncoding = RestAssured.given().when().relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie()).get(url("/crypto/encoding/basic")).then().extract()
        .asString();
    basicEncoding = basicEncoding.substring("Authorization: Basic ".length());
    String decodedString = new String(Base64.getDecoder().decode(basicEncoding.getBytes()));
    String answer_user = decodedString.split(":")[0];
    String answer_pwd = decodedString.split(":")[1];
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_user", answer_user);
    params.put("answer_pwd", answer_pwd);
    checkAssignment(url("/crypto/encoding/basic-auth"), params, true);
  }

  private void checkAssignment3() {
    String answer_1 = "databasepassword";
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    checkAssignment(url("/crypto/encoding/xor"), params, true);
  }

  private void checkAssignment4() throws NoSuchAlgorithmException {

    String md5Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/md5")).then().extract().asString();

    String sha256Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/sha256")).then().extract().asString();

    String answer_1 = "unknown";
    String answer_2 = "unknown";
    for (String secret : HashingAssignment.SECRETS) {
      if (md5Hash.equals(HashingAssignment.getHash(secret, "MD5"))) {
        answer_1 = secret;
      }
      if (sha256Hash.equals(HashingAssignment.getHash(secret, "SHA-256"))) {
        answer_2 = secret;
      }
    }

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    params.put("answer_pwd2", answer_2);
    checkAssignment(url("/WebGoat/crypto/hashing"), params, true);
  }

  private void checkAssignmentSigning() throws NoSuchAlgorithmException, InvalidKeySpecException {
      
      String privatePEM = RestAssured.given()
              .when()
              .relaxedHTTPSValidation()
              .cookie("JSESSIONID", getWebGoatCookie())
              .get(url("/crypto/signing/getprivate"))
              .then()
        .extract().asString();
    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(privatePEM);

    RSAPrivateKey privk = (RSAPrivateKey) privateKey;
    String modulus = DatatypeConverter.printHexBinary(privk.getModulus().toByteArray());
      String signature = CryptoUtil.signMessage(modulus, privateKey);
        Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("modulus", modulus);
        params.put("signature", signature);
        checkAssignment(url("/crypto/signing/verify"), params, true);
    }
  
  private void checkAssignmentDefaults() {
      
      String text = new String(Base64.getDecoder().decode("TGVhdmluZyBwYXNzd29yZHMgaW4gZG9ja2VyIGltYWdlcyBpcyBub3Qgc28gc2VjdXJl".getBytes(Charset.forName("UTF-8"))));

    Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("secretText", text);
        params.put("secretFileName", "default_secret");
        checkAssignment(url("/crypto/secure/defaults"), params, true);
    }
    
}


package org.owasp.webgoat;

import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.cryptography.CryptoUtil;
import org.owasp.webgoat.lessons.cryptography.HashingAssignment;

import io.restassured.RestAssured;

public class CryptoIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("Cryptography");

    checkAssignment2();
    checkAssignment3();

    // Assignment 4
    try {
      checkAssignment4();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      fail();
    }

    try {
      checkAssignmentSigning();
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
    
    checkAssignmentDefaults();

    checkResults("/crypto");

  }

  private void checkAssignment2() {

    String basicEncoding = RestAssured.given().when().relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie()).get(url("/crypto/encoding/basic")).then().extract()
        .asString();
    basicEncoding = basicEncoding.substring("Authorization: Basic ".length());
    String decodedString = new String(Base64.getDecoder().decode(basicEncoding.getBytes()));
    String answer_user = decodedString.split(":")[0];
    String answer_pwd = decodedString.split(":")[1];
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_user", answer_user);
    params.put("answer_pwd", answer_pwd);
    checkAssignment(url("/crypto/encoding/basic-auth"), params, true);
  }
HashingAssignment
  private void checkAssignment3() {
    String answer_1 = "databasepassword";
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    checkAssignment(url("/crypto/encoding/xor"), params, true);
  }

  private void checkAssignment4() throws NoSuchAlgorithmException {

    String md5Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/md5")).then().extract().asString();

    String sha256Hash = RestAssured.given().when().relaxedHTTPSValidation().cookie("JSESSIONID", getWebGoatCookie())
        .get(url("/crypto/hashing/sha256")).then().extract().asString();

    String answer_1 = "unknown";
    String answer_2 = "unknown";
    for (String secret : HashingAssignment.SECRETS) {
      if (md5Hash.equals(HashingAssignment.getHash(secret, "MD5"))) {
        answer_1 = secret;
      }
      if (sha256Hash.equals(HashingAssignment.getHash(secret, "SHA-256"))) {
        answer_2 = secret;
      }
    }

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    params.put("answer_pwd2", answer_2);
    checkAssignment(url("/WebGoat/crypto/hashing"), params, true);
  }

  private void checkAssignmentSigning() throws NoSuchAlgorithmException, InvalidKeySpecException {
      
      String privatePEM = RestAssured.given()
              .when()
              .relaxedHTTPSValidation()
              .cookie("JSESSIONID", getWebGoatCookie())
              .get(url("/crypto/signing/getprivate"))
              .then()
        .extract().asString();
    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(privatePEM);

    RSAPrivateKey privk = (RSAPrivateKey) privateKey;
    String modulus = DatatypeConverter.printHexBinary(privk.getModulus().toByteArray());
      String signature = CryptoUtil.signMessage(modulus, privateKey);
        Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("modulus", modulus);
        params.put("signature", signature);
        checkAssignment(url("/crypto/signing/verify"), params, true);
    }
  
  private void checkAssignmentDefaults() {
      
      String text = new String(Base64.getDecoder().decode("TGVhdmluZyBwYXNzd29yZHMgaW4gZG9ja2VyIGltYWdlcyBpcyBub3Qgc28gc2VjdXJl".getBytes(Charset.forName("UTF-8"))));

    Map<String, Object> params = new HashMap<>();
        params.clear();
        params.put("secretText", text);
        params.put("secretFileName", "default_secret");
        checkAssignment(url("/crypto/secure/defaults"), params, true);
    }
    
}



/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.RandomStringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.springframework.http.ResponseEntity.ok;

/**
 * @author nbaars
 * @since 4/23/17.
 */
@RestController
@AssignmentHints({"jwt-refresh-hint1", "jwt-refresh-hint2", "jwt-refresh-hint3", "jwt-refresh-hint4"})
public class JWTRefreshEndpoint extends AssignmentEndpoint {

    public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
    private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
    private static final List<String> validRefreshTokens = new ArrayList<>();

    @PostMapping(value = "/JWT/refresh/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
        if (json == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String user = (String) json.get("user");
        String password = (String) json.get("password");

        if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
            return ok(createNewTokens(user));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    private Map<String, Object> createNewTokens(String user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("admin", "false");
        claims.put("user", user);
        String token = Jwts.builder()
                .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
                .setClaims(claims)
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
                .compact();
        Map<String, Object> tokenJson = new HashMap<>();
        String refreshToken = RandomStringUtils.randomAlphabetic(20);
        validRefreshTokens.add(refreshToken);
        tokenJson.put("access_token", token);
        tokenJson.put("refresh_token", refreshToken);
        return tokenJson;
    }

    @PostMapping("/JWT/refresh/checkout")
    @ResponseBody
    public ResponseEntity<AttackResult> checkout(@RequestHeader(value = "Authorization", required = false) String token) {
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
            Claims claims = (Claims) jwt.getBody();
            String user = (String) claims.get("user");
            if ("Tom".equals(user)) {
                return ok(success(this).build());
            }
            return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
        } catch (ExpiredJwtException e) {
            return ok(failed(this).output(e.getMessage()).build());
        } catch (JwtException e) {
            return ok(failed(this).feedback("jwt-invalid-token").build());
        }
    }

    @PostMapping("/JWT/refresh/newToken")
    @ResponseBody
    public ResponseEntity newToken(@RequestHeader(value = "Authorization", required = false) String token,
                                   @RequestBody(required = false) Map<String, Object> json) {
        if (token == null || json == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String user;
        String refreshToken;
        try {
            Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
            user = (String) jwt.getBody().get("user");
            refreshToken = (String) json.get("refresh_token");
        } catch (ExpiredJwtException e) {
            user = (String) e.getClaims().get("user");
            refreshToken = (String) json.get("refresh_token");
        }

        if (user == null || refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } else if (validRefreshTokens.contains(refreshToken)) {
            validRefreshTokens.remove(refreshToken);
            return ok(createNewTokens(user));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}


