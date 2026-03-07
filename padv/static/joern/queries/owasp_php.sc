@main def main(inputPath: String, outputPath: String): Unit = {
  importCode(inputPath)

  import java.nio.charset.StandardCharsets
  import java.nio.file.{Files, Paths}
  import scala.collection.mutable.ArrayBuffer

  case class Rule(vulnClass: String, queryId: String, regex: scala.util.matching.Regex)

  val rules = List(
    Rule("sql_injection_boundary", "joern::sql_boundary", "(?i)(mysqli_query|mysqli_real_query|mysqli::query|mysqli_multi_query|pdo::query|pdo::prepare|pdo::exec|pg_query)".r),
    Rule("command_injection_boundary", "joern::cmd_boundary", "(?i)(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|`)".r),
    Rule("code_injection_boundary", "joern::code_boundary", "(?i)(eval|assert|preg_replace|create_function)".r),
    Rule("ldap_injection_boundary", "joern::ldap_boundary", "(?i)(ldap_search|ldap_list|ldap_read|ldap_add|ldap_modify)".r),
    Rule("xpath_injection_boundary", "joern::xpath_boundary", "(?i)(domxpath::query|domxpath::evaluate|simplexmlelement::xpath)".r),
    Rule("file_boundary_influence", "joern::file_boundary", "(?i)(file_put_contents|file_get_contents|fopen|include_once|include|require_once|require|readfile|show_source|highlight_file)".r),
    Rule("file_upload_influence", "joern::upload_boundary", "(?i)(move_uploaded_file|finfo_file|mime_content_type)".r),
    Rule("xss_output_boundary", "joern::xss_boundary", "(?i)(\\becho\\b|printf|vprintf|die|exit|\\bprint\\b)".r),
    Rule("debug_output_leak", "joern::debug_output", "(?i)(print_r|var_dump|var_export|phpinfo)".r),
    Rule("outbound_request_influence", "joern::outbound_boundary", "(?i)(curl_exec|curl_setopt|curlopt_url|file_get_contents|fopen|fsockopen|pfsockopen)".r),
    Rule("xxe_influence", "joern::xxe_boundary", "(?i)(domdocument::loadxml|domdocument::load|simplexml_load_file|simplexml_load_string|xml_parse)".r),
    Rule("deserialization_influence", "joern::deser_boundary", "(?i)(unserialize|json_decode)".r),
    Rule("php_object_gadget_surface", "joern::gadget_surface", "(?i)(__wakeup|__destruct|__tostring|__call|__get|__set)".r),
    Rule("header_injection_boundary", "joern::header_boundary", "(?i)(header|mail|mb_send_mail)".r),
    Rule("regex_dos_boundary", "joern::regex_dos", "(?i)(preg_match|preg_match_all|preg_replace|max_input_vars)".r),
    Rule("xml_dos_boundary", "joern::xml_dos", "(?i)(domdocument::loadxml|simplexml_load_string|xml_parse)".r),
    Rule("broken_access_control", "joern::access_control", "(?i)(authorize|is_admin|role|permission)".r),
    Rule("csrf_invariant_missing", "joern::csrf_invariant", "(?i)(hash_equals|csrf|csrf_token|token)".r),
    Rule("idor_invariant_missing", "joern::idor_invariant", "(?i)(findbyid|getbyid|loadbyid)".r),
    Rule("session_fixation_invariant", "joern::session_fixation", "(?i)(session_start|session_regenerate_id)".r),
    Rule("crypto_failures", "joern::crypto", "(?i)(md5|sha1|openssl_encrypt|openssl_decrypt|crypt|rand|mt_rand|uniqid|shuffle|array_rand)".r),
    Rule("security_misconfiguration", "joern::misconfig", "(?i)(ini_set|display_errors|error_reporting)".r),
    Rule("insecure_design", "joern::insecure_design", "(?i)(allow_all_access|bypass_auth|skip_authorization|trust_client_role)".r),
    Rule("auth_and_session_failures", "joern::auth_session", "(?i)(session_start|password_verify|setcookie)".r),
    Rule("software_data_integrity", "joern::integrity", "(?i)(eval|assert|include|require)".r),
    Rule("logging_monitoring_failures", "joern::logging", "(?i)(error_log|logger|audit)".r),
    Rule("ssrf", "joern::ssrf", "(?i)(curl_exec|curl_setopt|curlopt_url|file_get_contents|fopen|fsockopen|pfsockopen)".r),
    Rule("information_disclosure", "joern::info_disclosure", "(?i)(phpinfo|display_errors|print_r|var_dump|var_export)".r)
  )

  def esc(value: String): String = {
    value
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r")
      .replace("\t", "\\t")
  }

  val out = ArrayBuffer[String]()

  val calls = cpg.call.l
  for (rule <- rules) {
    for (call <- calls) {
      val name = Option(call.name).getOrElse("")
      val code = Option(call.code).getOrElse("")
      if (rule.regex.findFirstIn(name).nonEmpty || rule.regex.findFirstIn(code).nonEmpty) {
        val filePath = call.file.name.headOption.getOrElse("")
        val line = call.lineNumber.getOrElse(0)
        val sink = if (name.nonEmpty) name else "unknown"
        val snippet = code.take(240)

        out += s"{\"vuln_class\":\"${esc(rule.vulnClass)}\",\"query_id\":\"${esc(rule.queryId)}\",\"file_path\":\"${esc(filePath)}\",\"line\":${line},\"sink\":\"${esc(sink)}\",\"snippet\":\"${esc(snippet)}\"}"
      }
    }
  }

  Files.writeString(
    Paths.get(outputPath),
    out.mkString("\n"),
    StandardCharsets.UTF_8
  )
}
