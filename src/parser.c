#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef _MSC_VER
#pragma optimize("", off)
#elif defined(__clang__)
#pragma clang optimize off
#elif defined(__GNUC__)
#pragma GCC optimize ("O0")
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 251
#define LARGE_STATE_COUNT 51
#define SYMBOL_COUNT 201
#define ALIAS_COUNT 0
#define TOKEN_COUNT 159
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 16
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 22

enum {
  anon_sym_in = 1,
  anon_sym_AMP_AMP = 2,
  anon_sym_and = 3,
  anon_sym_xor = 4,
  anon_sym_CARET_CARET = 5,
  anon_sym_or = 6,
  anon_sym_PIPE_PIPE = 7,
  anon_sym_LBRACE = 8,
  anon_sym_RBRACE = 9,
  sym_comment = 10,
  anon_sym_eq = 11,
  anon_sym_ne = 12,
  anon_sym_lt = 13,
  anon_sym_le = 14,
  anon_sym_gt = 15,
  anon_sym_ge = 16,
  anon_sym_EQ_EQ = 17,
  anon_sym_BANG_EQ = 18,
  anon_sym_LT = 19,
  anon_sym_LT_EQ = 20,
  anon_sym_GT = 21,
  anon_sym_GT_EQ = 22,
  anon_sym_contains = 23,
  anon_sym_matches = 24,
  anon_sym_TILDE = 25,
  anon_sym_concat = 26,
  anon_sym_LPAREN = 27,
  anon_sym_COMMA = 28,
  anon_sym_RPAREN = 29,
  anon_sym_lookup_json_string = 30,
  anon_sym_lower = 31,
  anon_sym_regex_replace = 32,
  anon_sym_remove_bytes = 33,
  anon_sym_to_string = 34,
  anon_sym_upper = 35,
  anon_sym_url_decode = 36,
  anon_sym_uuidv4 = 37,
  anon_sym_len = 38,
  anon_sym_ends_with = 39,
  anon_sym_starts_with = 40,
  anon_sym_any = 41,
  anon_sym_all = 42,
  anon_sym_LBRACK_STAR_RBRACK = 43,
  sym_number = 44,
  sym_string = 45,
  anon_sym_true = 46,
  anon_sym_false = 47,
  sym_ipv4 = 48,
  anon_sym_SLASH = 49,
  aux_sym_ip_range_token1 = 50,
  sym_ip_list = 51,
  anon_sym_not = 52,
  anon_sym_BANG = 53,
  anon_sym_LBRACK = 54,
  anon_sym_RBRACK = 55,
  anon_sym_STAR = 56,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 57,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 58,
  anon_sym_ip_DOTgeoip_DOTasnum = 59,
  anon_sym_cf_DOTbot_management_DOTscore = 60,
  anon_sym_cf_DOTedge_DOTserver_port = 61,
  anon_sym_cf_DOTthreat_score = 62,
  anon_sym_cf_DOTwaf_DOTscore = 63,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 64,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 65,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 66,
  anon_sym_icmp_DOTtype = 67,
  anon_sym_icmp_DOTcode = 68,
  anon_sym_ip_DOThdr_len = 69,
  anon_sym_ip_DOTlen = 70,
  anon_sym_ip_DOTopt_DOTtype = 71,
  anon_sym_ip_DOTttl = 72,
  anon_sym_tcp_DOTflags = 73,
  anon_sym_tcp_DOTsrcport = 74,
  anon_sym_tcp_DOTdstport = 75,
  anon_sym_udp_DOTdstport = 76,
  anon_sym_udp_DOTsrcport = 77,
  anon_sym_http_DOTrequest_DOTbody_DOTsize = 78,
  anon_sym_http_DOTresponse_DOTcode = 79,
  anon_sym_http_DOTresponse_DOT1xxx_code = 80,
  anon_sym_ip_DOTsrc = 81,
  anon_sym_cf_DOTedge_DOTserver_ip = 82,
  anon_sym_ip_DOTdst = 83,
  anon_sym_http_DOTcookie = 84,
  anon_sym_http_DOThost = 85,
  anon_sym_http_DOTreferer = 86,
  anon_sym_http_DOTrequest_DOTfull_uri = 87,
  anon_sym_http_DOTrequest_DOTmethod = 88,
  anon_sym_http_DOTrequest_DOTuri = 89,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 90,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 91,
  anon_sym_http_DOTuser_agent = 92,
  anon_sym_http_DOTrequest_DOTversion = 93,
  anon_sym_http_DOTx_forwarded_for = 94,
  anon_sym_ip_DOTsrc_DOTlat = 95,
  anon_sym_ip_DOTsrc_DOTlon = 96,
  anon_sym_ip_DOTsrc_DOTcity = 97,
  anon_sym_ip_DOTsrc_DOTpostal_code = 98,
  anon_sym_ip_DOTsrc_DOTmetro_code = 99,
  anon_sym_ip_DOTgeoip_DOTcontinent = 100,
  anon_sym_ip_DOTgeoip_DOTcountry = 101,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 102,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 103,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 104,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 105,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 106,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 107,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 108,
  anon_sym_cf_DOThostname_DOTmetadata = 109,
  anon_sym_cf_DOTworker_DOTupstream_zone = 110,
  anon_sym_cf_DOTcolo_DOTname = 111,
  anon_sym_cf_DOTcolo_DOTregion = 112,
  anon_sym_icmp = 113,
  anon_sym_ip = 114,
  anon_sym_ip_DOTdst_DOTcountry = 115,
  anon_sym_ip_DOTsrc_DOTcountry = 116,
  anon_sym_tcp = 117,
  anon_sym_udp = 118,
  anon_sym_http_DOTrequest_DOTbody_DOTraw = 119,
  anon_sym_http_DOTrequest_DOTbody_DOTmime = 120,
  anon_sym_cf_DOTresponse_DOTerror_type = 121,
  anon_sym_cf_DOTrandom_seed = 122,
  anon_sym_http_DOTrequest_DOTcookies = 123,
  anon_sym_http_DOTrequest_DOTuri_DOTargs = 124,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs = 125,
  anon_sym_http_DOTrequest_DOTheaders = 126,
  anon_sym_http_DOTrequest_DOTbody_DOTform = 127,
  anon_sym_http_DOTresponse_DOTheaders = 128,
  anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames = 129,
  anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues = 130,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames = 131,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues = 132,
  anon_sym_http_DOTrequest_DOTheaders_DOTnames = 133,
  anon_sym_http_DOTrequest_DOTheaders_DOTvalues = 134,
  anon_sym_http_DOTrequest_DOTaccepted_languages = 135,
  anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames = 136,
  anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues = 137,
  anon_sym_http_DOTresponse_DOTheaders_DOTnames = 138,
  anon_sym_http_DOTresponse_DOTheaders_DOTvalues = 139,
  anon_sym_cf_DOTbot_management_DOTdetection_ids = 140,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 141,
  anon_sym_ssl = 142,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 143,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 144,
  anon_sym_cf_DOTclient_DOTbot = 145,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 146,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 147,
  anon_sym_sip = 148,
  anon_sym_tcp_DOTflags_DOTack = 149,
  anon_sym_tcp_DOTflags_DOTcwr = 150,
  anon_sym_tcp_DOTflags_DOTecn = 151,
  anon_sym_tcp_DOTflags_DOTfin = 152,
  anon_sym_tcp_DOTflags_DOTpush = 153,
  anon_sym_tcp_DOTflags_DOTreset = 154,
  anon_sym_tcp_DOTflags_DOTsyn = 155,
  anon_sym_tcp_DOTflags_DOTurg = 156,
  anon_sym_http_DOTrequest_DOTheaders_DOTtruncated = 157,
  anon_sym_http_DOTrequest_DOTbody_DOTtruncated = 158,
  sym_source_file = 159,
  sym__expression = 160,
  sym_not_expression = 161,
  sym_in_expression = 162,
  sym_compound_expression = 163,
  sym_ip_set = 164,
  sym_string_set = 165,
  sym_number_set = 166,
  sym_simple_expression = 167,
  sym__bool_lhs = 168,
  sym__number_lhs = 169,
  sym__string_lhs = 170,
  sym_string_func = 171,
  sym_number_func = 172,
  sym_bool_func = 173,
  sym_array_func = 174,
  sym_group = 175,
  sym_boolean = 176,
  sym__ip = 177,
  sym_ip_range = 178,
  sym_not_operator = 179,
  sym_number_array = 180,
  sym_bool_array = 181,
  sym_string_array = 182,
  sym__string_array_expansion = 183,
  sym_boollike_field = 184,
  sym_numberlike_field = 185,
  sym_stringlike_field = 186,
  sym_number_field = 187,
  sym_ip_field = 188,
  sym_string_field = 189,
  sym_bytes_field = 190,
  sym_map_string_array_field = 191,
  sym_array_string_field = 192,
  sym_array_number_field = 193,
  sym_bool_field = 194,
  aux_sym_source_file_repeat1 = 195,
  aux_sym_ip_set_repeat1 = 196,
  aux_sym_string_set_repeat1 = 197,
  aux_sym_number_set_repeat1 = 198,
  aux_sym_string_func_repeat1 = 199,
  aux_sym_string_func_repeat2 = 200,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_in] = "in",
  [anon_sym_AMP_AMP] = "&&",
  [anon_sym_and] = "and",
  [anon_sym_xor] = "xor",
  [anon_sym_CARET_CARET] = "^^",
  [anon_sym_or] = "or",
  [anon_sym_PIPE_PIPE] = "||",
  [anon_sym_LBRACE] = "{",
  [anon_sym_RBRACE] = "}",
  [sym_comment] = "comment",
  [anon_sym_eq] = "eq",
  [anon_sym_ne] = "ne",
  [anon_sym_lt] = "lt",
  [anon_sym_le] = "le",
  [anon_sym_gt] = "gt",
  [anon_sym_ge] = "ge",
  [anon_sym_EQ_EQ] = "==",
  [anon_sym_BANG_EQ] = "!=",
  [anon_sym_LT] = "<",
  [anon_sym_LT_EQ] = "<=",
  [anon_sym_GT] = ">",
  [anon_sym_GT_EQ] = ">=",
  [anon_sym_contains] = "contains",
  [anon_sym_matches] = "matches",
  [anon_sym_TILDE] = "~",
  [anon_sym_concat] = "concat",
  [anon_sym_LPAREN] = "(",
  [anon_sym_COMMA] = ",",
  [anon_sym_RPAREN] = ")",
  [anon_sym_lookup_json_string] = "lookup_json_string",
  [anon_sym_lower] = "lower",
  [anon_sym_regex_replace] = "regex_replace",
  [anon_sym_remove_bytes] = "remove_bytes",
  [anon_sym_to_string] = "to_string",
  [anon_sym_upper] = "upper",
  [anon_sym_url_decode] = "url_decode",
  [anon_sym_uuidv4] = "uuidv4",
  [anon_sym_len] = "len",
  [anon_sym_ends_with] = "ends_with",
  [anon_sym_starts_with] = "starts_with",
  [anon_sym_any] = "any",
  [anon_sym_all] = "all",
  [anon_sym_LBRACK_STAR_RBRACK] = "[*]",
  [sym_number] = "number",
  [sym_string] = "string",
  [anon_sym_true] = "true",
  [anon_sym_false] = "false",
  [sym_ipv4] = "ipv4",
  [anon_sym_SLASH] = "/",
  [aux_sym_ip_range_token1] = "ip_range_token1",
  [sym_ip_list] = "ip_list",
  [anon_sym_not] = "not",
  [anon_sym_BANG] = "!",
  [anon_sym_LBRACK] = "[",
  [anon_sym_RBRACK] = "]",
  [anon_sym_STAR] = "*",
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = "http.request.timestamp.sec",
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = "http.request.timestamp.msec",
  [anon_sym_ip_DOTgeoip_DOTasnum] = "ip.geoip.asnum",
  [anon_sym_cf_DOTbot_management_DOTscore] = "cf.bot_management.score",
  [anon_sym_cf_DOTedge_DOTserver_port] = "cf.edge.server_port",
  [anon_sym_cf_DOTthreat_score] = "cf.threat_score",
  [anon_sym_cf_DOTwaf_DOTscore] = "cf.waf.score",
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = "cf.waf.score.sqli",
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = "cf.waf.score.xss",
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = "cf.waf.score.rce",
  [anon_sym_icmp_DOTtype] = "icmp.type",
  [anon_sym_icmp_DOTcode] = "icmp.code",
  [anon_sym_ip_DOThdr_len] = "ip.hdr_len",
  [anon_sym_ip_DOTlen] = "ip.len",
  [anon_sym_ip_DOTopt_DOTtype] = "ip.opt.type",
  [anon_sym_ip_DOTttl] = "ip.ttl",
  [anon_sym_tcp_DOTflags] = "tcp.flags",
  [anon_sym_tcp_DOTsrcport] = "tcp.srcport",
  [anon_sym_tcp_DOTdstport] = "tcp.dstport",
  [anon_sym_udp_DOTdstport] = "udp.dstport",
  [anon_sym_udp_DOTsrcport] = "udp.srcport",
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = "http.request.body.size",
  [anon_sym_http_DOTresponse_DOTcode] = "http.response.code",
  [anon_sym_http_DOTresponse_DOT1xxx_code] = "http.response.1xxx_code",
  [anon_sym_ip_DOTsrc] = "ip.src",
  [anon_sym_cf_DOTedge_DOTserver_ip] = "cf.edge.server_ip",
  [anon_sym_ip_DOTdst] = "ip.dst",
  [anon_sym_http_DOTcookie] = "http.cookie",
  [anon_sym_http_DOThost] = "http.host",
  [anon_sym_http_DOTreferer] = "http.referer",
  [anon_sym_http_DOTrequest_DOTfull_uri] = "http.request.full_uri",
  [anon_sym_http_DOTrequest_DOTmethod] = "http.request.method",
  [anon_sym_http_DOTrequest_DOTuri] = "http.request.uri",
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = "http.request.uri.path",
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = "http.request.uri.query",
  [anon_sym_http_DOTuser_agent] = "http.user_agent",
  [anon_sym_http_DOTrequest_DOTversion] = "http.request.version",
  [anon_sym_http_DOTx_forwarded_for] = "http.x_forwarded_for",
  [anon_sym_ip_DOTsrc_DOTlat] = "ip.src.lat",
  [anon_sym_ip_DOTsrc_DOTlon] = "ip.src.lon",
  [anon_sym_ip_DOTsrc_DOTcity] = "ip.src.city",
  [anon_sym_ip_DOTsrc_DOTpostal_code] = "ip.src.postal_code",
  [anon_sym_ip_DOTsrc_DOTmetro_code] = "ip.src.metro_code",
  [anon_sym_ip_DOTgeoip_DOTcontinent] = "ip.geoip.continent",
  [anon_sym_ip_DOTgeoip_DOTcountry] = "ip.geoip.country",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = "ip.geoip.subdivision_1_iso_code",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = "ip.geoip.subdivision_2_iso_code",
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = "raw.http.request.full_uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = "raw.http.request.uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = "raw.http.request.uri.path",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = "raw.http.request.uri.query",
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = "cf.bot_management.ja3_hash",
  [anon_sym_cf_DOThostname_DOTmetadata] = "cf.hostname.metadata",
  [anon_sym_cf_DOTworker_DOTupstream_zone] = "cf.worker.upstream_zone",
  [anon_sym_cf_DOTcolo_DOTname] = "cf.colo.name",
  [anon_sym_cf_DOTcolo_DOTregion] = "cf.colo.region",
  [anon_sym_icmp] = "icmp",
  [anon_sym_ip] = "ip",
  [anon_sym_ip_DOTdst_DOTcountry] = "ip.dst.country",
  [anon_sym_ip_DOTsrc_DOTcountry] = "ip.src.country",
  [anon_sym_tcp] = "tcp",
  [anon_sym_udp] = "udp",
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = "http.request.body.raw",
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = "http.request.body.mime",
  [anon_sym_cf_DOTresponse_DOTerror_type] = "cf.response.error_type",
  [anon_sym_cf_DOTrandom_seed] = "cf.random_seed",
  [anon_sym_http_DOTrequest_DOTcookies] = "http.request.cookies",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = "http.request.uri.args",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = "raw.http.request.uri.args",
  [anon_sym_http_DOTrequest_DOTheaders] = "http.request.headers",
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = "http.request.body.form",
  [anon_sym_http_DOTresponse_DOTheaders] = "http.response.headers",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = "http.request.uri.args.names",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = "http.request.uri.args.values",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = "raw.http.request.uri.args.names",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = "raw.http.request.uri.args.values",
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = "http.request.headers.names",
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = "http.request.headers.values",
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = "http.request.accepted_languages",
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = "http.request.body.form.names",
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = "http.request.body.form.values",
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = "http.response.headers.names",
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = "http.response.headers.values",
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = "cf.bot_management.detection_ids",
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = "ip.geoip.is_in_european_union",
  [anon_sym_ssl] = "ssl",
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = "cf.bot_management.verified_bot",
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = "cf.bot_management.js_detection.passed",
  [anon_sym_cf_DOTclient_DOTbot] = "cf.client.bot",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = "cf.tls_client_auth.cert_revoked",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = "cf.tls_client_auth.cert_verified",
  [anon_sym_sip] = "sip",
  [anon_sym_tcp_DOTflags_DOTack] = "tcp.flags.ack",
  [anon_sym_tcp_DOTflags_DOTcwr] = "tcp.flags.cwr",
  [anon_sym_tcp_DOTflags_DOTecn] = "tcp.flags.ecn",
  [anon_sym_tcp_DOTflags_DOTfin] = "tcp.flags.fin",
  [anon_sym_tcp_DOTflags_DOTpush] = "tcp.flags.push",
  [anon_sym_tcp_DOTflags_DOTreset] = "tcp.flags.reset",
  [anon_sym_tcp_DOTflags_DOTsyn] = "tcp.flags.syn",
  [anon_sym_tcp_DOTflags_DOTurg] = "tcp.flags.urg",
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = "http.request.headers.truncated",
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = "http.request.body.truncated",
  [sym_source_file] = "source_file",
  [sym__expression] = "_expression",
  [sym_not_expression] = "not_expression",
  [sym_in_expression] = "in_expression",
  [sym_compound_expression] = "compound_expression",
  [sym_ip_set] = "ip_set",
  [sym_string_set] = "string_set",
  [sym_number_set] = "number_set",
  [sym_simple_expression] = "simple_expression",
  [sym__bool_lhs] = "_bool_lhs",
  [sym__number_lhs] = "_number_lhs",
  [sym__string_lhs] = "_string_lhs",
  [sym_string_func] = "string_func",
  [sym_number_func] = "number_func",
  [sym_bool_func] = "bool_func",
  [sym_array_func] = "array_func",
  [sym_group] = "group",
  [sym_boolean] = "boolean",
  [sym__ip] = "_ip",
  [sym_ip_range] = "ip_range",
  [sym_not_operator] = "not_operator",
  [sym_number_array] = "number_array",
  [sym_bool_array] = "bool_array",
  [sym_string_array] = "string_array",
  [sym__string_array_expansion] = "_string_array_expansion",
  [sym_boollike_field] = "boollike_field",
  [sym_numberlike_field] = "numberlike_field",
  [sym_stringlike_field] = "stringlike_field",
  [sym_number_field] = "number_field",
  [sym_ip_field] = "ip_field",
  [sym_string_field] = "string_field",
  [sym_bytes_field] = "bytes_field",
  [sym_map_string_array_field] = "map_string_array_field",
  [sym_array_string_field] = "array_string_field",
  [sym_array_number_field] = "array_number_field",
  [sym_bool_field] = "bool_field",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
  [aux_sym_ip_set_repeat1] = "ip_set_repeat1",
  [aux_sym_string_set_repeat1] = "string_set_repeat1",
  [aux_sym_number_set_repeat1] = "number_set_repeat1",
  [aux_sym_string_func_repeat1] = "string_func_repeat1",
  [aux_sym_string_func_repeat2] = "string_func_repeat2",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [anon_sym_in] = anon_sym_in,
  [anon_sym_AMP_AMP] = anon_sym_AMP_AMP,
  [anon_sym_and] = anon_sym_and,
  [anon_sym_xor] = anon_sym_xor,
  [anon_sym_CARET_CARET] = anon_sym_CARET_CARET,
  [anon_sym_or] = anon_sym_or,
  [anon_sym_PIPE_PIPE] = anon_sym_PIPE_PIPE,
  [anon_sym_LBRACE] = anon_sym_LBRACE,
  [anon_sym_RBRACE] = anon_sym_RBRACE,
  [sym_comment] = sym_comment,
  [anon_sym_eq] = anon_sym_eq,
  [anon_sym_ne] = anon_sym_ne,
  [anon_sym_lt] = anon_sym_lt,
  [anon_sym_le] = anon_sym_le,
  [anon_sym_gt] = anon_sym_gt,
  [anon_sym_ge] = anon_sym_ge,
  [anon_sym_EQ_EQ] = anon_sym_EQ_EQ,
  [anon_sym_BANG_EQ] = anon_sym_BANG_EQ,
  [anon_sym_LT] = anon_sym_LT,
  [anon_sym_LT_EQ] = anon_sym_LT_EQ,
  [anon_sym_GT] = anon_sym_GT,
  [anon_sym_GT_EQ] = anon_sym_GT_EQ,
  [anon_sym_contains] = anon_sym_contains,
  [anon_sym_matches] = anon_sym_matches,
  [anon_sym_TILDE] = anon_sym_TILDE,
  [anon_sym_concat] = anon_sym_concat,
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_COMMA] = anon_sym_COMMA,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [anon_sym_lookup_json_string] = anon_sym_lookup_json_string,
  [anon_sym_lower] = anon_sym_lower,
  [anon_sym_regex_replace] = anon_sym_regex_replace,
  [anon_sym_remove_bytes] = anon_sym_remove_bytes,
  [anon_sym_to_string] = anon_sym_to_string,
  [anon_sym_upper] = anon_sym_upper,
  [anon_sym_url_decode] = anon_sym_url_decode,
  [anon_sym_uuidv4] = anon_sym_uuidv4,
  [anon_sym_len] = anon_sym_len,
  [anon_sym_ends_with] = anon_sym_ends_with,
  [anon_sym_starts_with] = anon_sym_starts_with,
  [anon_sym_any] = anon_sym_any,
  [anon_sym_all] = anon_sym_all,
  [anon_sym_LBRACK_STAR_RBRACK] = anon_sym_LBRACK_STAR_RBRACK,
  [sym_number] = sym_number,
  [sym_string] = sym_string,
  [anon_sym_true] = anon_sym_true,
  [anon_sym_false] = anon_sym_false,
  [sym_ipv4] = sym_ipv4,
  [anon_sym_SLASH] = anon_sym_SLASH,
  [aux_sym_ip_range_token1] = aux_sym_ip_range_token1,
  [sym_ip_list] = sym_ip_list,
  [anon_sym_not] = anon_sym_not,
  [anon_sym_BANG] = anon_sym_BANG,
  [anon_sym_LBRACK] = anon_sym_LBRACK,
  [anon_sym_RBRACK] = anon_sym_RBRACK,
  [anon_sym_STAR] = anon_sym_STAR,
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
  [anon_sym_ip_DOTgeoip_DOTasnum] = anon_sym_ip_DOTgeoip_DOTasnum,
  [anon_sym_cf_DOTbot_management_DOTscore] = anon_sym_cf_DOTbot_management_DOTscore,
  [anon_sym_cf_DOTedge_DOTserver_port] = anon_sym_cf_DOTedge_DOTserver_port,
  [anon_sym_cf_DOTthreat_score] = anon_sym_cf_DOTthreat_score,
  [anon_sym_cf_DOTwaf_DOTscore] = anon_sym_cf_DOTwaf_DOTscore,
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = anon_sym_cf_DOTwaf_DOTscore_DOTxss,
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = anon_sym_cf_DOTwaf_DOTscore_DOTrce,
  [anon_sym_icmp_DOTtype] = anon_sym_icmp_DOTtype,
  [anon_sym_icmp_DOTcode] = anon_sym_icmp_DOTcode,
  [anon_sym_ip_DOThdr_len] = anon_sym_ip_DOThdr_len,
  [anon_sym_ip_DOTlen] = anon_sym_ip_DOTlen,
  [anon_sym_ip_DOTopt_DOTtype] = anon_sym_ip_DOTopt_DOTtype,
  [anon_sym_ip_DOTttl] = anon_sym_ip_DOTttl,
  [anon_sym_tcp_DOTflags] = anon_sym_tcp_DOTflags,
  [anon_sym_tcp_DOTsrcport] = anon_sym_tcp_DOTsrcport,
  [anon_sym_tcp_DOTdstport] = anon_sym_tcp_DOTdstport,
  [anon_sym_udp_DOTdstport] = anon_sym_udp_DOTdstport,
  [anon_sym_udp_DOTsrcport] = anon_sym_udp_DOTsrcport,
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = anon_sym_http_DOTrequest_DOTbody_DOTsize,
  [anon_sym_http_DOTresponse_DOTcode] = anon_sym_http_DOTresponse_DOTcode,
  [anon_sym_http_DOTresponse_DOT1xxx_code] = anon_sym_http_DOTresponse_DOT1xxx_code,
  [anon_sym_ip_DOTsrc] = anon_sym_ip_DOTsrc,
  [anon_sym_cf_DOTedge_DOTserver_ip] = anon_sym_cf_DOTedge_DOTserver_ip,
  [anon_sym_ip_DOTdst] = anon_sym_ip_DOTdst,
  [anon_sym_http_DOTcookie] = anon_sym_http_DOTcookie,
  [anon_sym_http_DOThost] = anon_sym_http_DOThost,
  [anon_sym_http_DOTreferer] = anon_sym_http_DOTreferer,
  [anon_sym_http_DOTrequest_DOTfull_uri] = anon_sym_http_DOTrequest_DOTfull_uri,
  [anon_sym_http_DOTrequest_DOTmethod] = anon_sym_http_DOTrequest_DOTmethod,
  [anon_sym_http_DOTrequest_DOTuri] = anon_sym_http_DOTrequest_DOTuri,
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = anon_sym_http_DOTrequest_DOTuri_DOTpath,
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = anon_sym_http_DOTrequest_DOTuri_DOTquery,
  [anon_sym_http_DOTuser_agent] = anon_sym_http_DOTuser_agent,
  [anon_sym_http_DOTrequest_DOTversion] = anon_sym_http_DOTrequest_DOTversion,
  [anon_sym_http_DOTx_forwarded_for] = anon_sym_http_DOTx_forwarded_for,
  [anon_sym_ip_DOTsrc_DOTlat] = anon_sym_ip_DOTsrc_DOTlat,
  [anon_sym_ip_DOTsrc_DOTlon] = anon_sym_ip_DOTsrc_DOTlon,
  [anon_sym_ip_DOTsrc_DOTcity] = anon_sym_ip_DOTsrc_DOTcity,
  [anon_sym_ip_DOTsrc_DOTpostal_code] = anon_sym_ip_DOTsrc_DOTpostal_code,
  [anon_sym_ip_DOTsrc_DOTmetro_code] = anon_sym_ip_DOTsrc_DOTmetro_code,
  [anon_sym_ip_DOTgeoip_DOTcontinent] = anon_sym_ip_DOTgeoip_DOTcontinent,
  [anon_sym_ip_DOTgeoip_DOTcountry] = anon_sym_ip_DOTgeoip_DOTcountry,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = anon_sym_raw_DOThttp_DOTrequest_DOTuri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = anon_sym_cf_DOTbot_management_DOTja3_hash,
  [anon_sym_cf_DOThostname_DOTmetadata] = anon_sym_cf_DOThostname_DOTmetadata,
  [anon_sym_cf_DOTworker_DOTupstream_zone] = anon_sym_cf_DOTworker_DOTupstream_zone,
  [anon_sym_cf_DOTcolo_DOTname] = anon_sym_cf_DOTcolo_DOTname,
  [anon_sym_cf_DOTcolo_DOTregion] = anon_sym_cf_DOTcolo_DOTregion,
  [anon_sym_icmp] = anon_sym_icmp,
  [anon_sym_ip] = anon_sym_ip,
  [anon_sym_ip_DOTdst_DOTcountry] = anon_sym_ip_DOTdst_DOTcountry,
  [anon_sym_ip_DOTsrc_DOTcountry] = anon_sym_ip_DOTsrc_DOTcountry,
  [anon_sym_tcp] = anon_sym_tcp,
  [anon_sym_udp] = anon_sym_udp,
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = anon_sym_http_DOTrequest_DOTbody_DOTraw,
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = anon_sym_http_DOTrequest_DOTbody_DOTmime,
  [anon_sym_cf_DOTresponse_DOTerror_type] = anon_sym_cf_DOTresponse_DOTerror_type,
  [anon_sym_cf_DOTrandom_seed] = anon_sym_cf_DOTrandom_seed,
  [anon_sym_http_DOTrequest_DOTcookies] = anon_sym_http_DOTrequest_DOTcookies,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = anon_sym_http_DOTrequest_DOTuri_DOTargs,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
  [anon_sym_http_DOTrequest_DOTheaders] = anon_sym_http_DOTrequest_DOTheaders,
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = anon_sym_http_DOTrequest_DOTbody_DOTform,
  [anon_sym_http_DOTresponse_DOTheaders] = anon_sym_http_DOTresponse_DOTheaders,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = anon_sym_http_DOTrequest_DOTheaders_DOTnames,
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = anon_sym_http_DOTrequest_DOTaccepted_languages,
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = anon_sym_http_DOTresponse_DOTheaders_DOTnames,
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = anon_sym_cf_DOTbot_management_DOTdetection_ids,
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = anon_sym_ip_DOTgeoip_DOTis_in_european_union,
  [anon_sym_ssl] = anon_sym_ssl,
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = anon_sym_cf_DOTbot_management_DOTverified_bot,
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
  [anon_sym_cf_DOTclient_DOTbot] = anon_sym_cf_DOTclient_DOTbot,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
  [anon_sym_sip] = anon_sym_sip,
  [anon_sym_tcp_DOTflags_DOTack] = anon_sym_tcp_DOTflags_DOTack,
  [anon_sym_tcp_DOTflags_DOTcwr] = anon_sym_tcp_DOTflags_DOTcwr,
  [anon_sym_tcp_DOTflags_DOTecn] = anon_sym_tcp_DOTflags_DOTecn,
  [anon_sym_tcp_DOTflags_DOTfin] = anon_sym_tcp_DOTflags_DOTfin,
  [anon_sym_tcp_DOTflags_DOTpush] = anon_sym_tcp_DOTflags_DOTpush,
  [anon_sym_tcp_DOTflags_DOTreset] = anon_sym_tcp_DOTflags_DOTreset,
  [anon_sym_tcp_DOTflags_DOTsyn] = anon_sym_tcp_DOTflags_DOTsyn,
  [anon_sym_tcp_DOTflags_DOTurg] = anon_sym_tcp_DOTflags_DOTurg,
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = anon_sym_http_DOTrequest_DOTbody_DOTtruncated,
  [sym_source_file] = sym_source_file,
  [sym__expression] = sym__expression,
  [sym_not_expression] = sym_not_expression,
  [sym_in_expression] = sym_in_expression,
  [sym_compound_expression] = sym_compound_expression,
  [sym_ip_set] = sym_ip_set,
  [sym_string_set] = sym_string_set,
  [sym_number_set] = sym_number_set,
  [sym_simple_expression] = sym_simple_expression,
  [sym__bool_lhs] = sym__bool_lhs,
  [sym__number_lhs] = sym__number_lhs,
  [sym__string_lhs] = sym__string_lhs,
  [sym_string_func] = sym_string_func,
  [sym_number_func] = sym_number_func,
  [sym_bool_func] = sym_bool_func,
  [sym_array_func] = sym_array_func,
  [sym_group] = sym_group,
  [sym_boolean] = sym_boolean,
  [sym__ip] = sym__ip,
  [sym_ip_range] = sym_ip_range,
  [sym_not_operator] = sym_not_operator,
  [sym_number_array] = sym_number_array,
  [sym_bool_array] = sym_bool_array,
  [sym_string_array] = sym_string_array,
  [sym__string_array_expansion] = sym__string_array_expansion,
  [sym_boollike_field] = sym_boollike_field,
  [sym_numberlike_field] = sym_numberlike_field,
  [sym_stringlike_field] = sym_stringlike_field,
  [sym_number_field] = sym_number_field,
  [sym_ip_field] = sym_ip_field,
  [sym_string_field] = sym_string_field,
  [sym_bytes_field] = sym_bytes_field,
  [sym_map_string_array_field] = sym_map_string_array_field,
  [sym_array_string_field] = sym_array_string_field,
  [sym_array_number_field] = sym_array_number_field,
  [sym_bool_field] = sym_bool_field,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
  [aux_sym_ip_set_repeat1] = aux_sym_ip_set_repeat1,
  [aux_sym_string_set_repeat1] = aux_sym_string_set_repeat1,
  [aux_sym_number_set_repeat1] = aux_sym_number_set_repeat1,
  [aux_sym_string_func_repeat1] = aux_sym_string_func_repeat1,
  [aux_sym_string_func_repeat2] = aux_sym_string_func_repeat2,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
    .named = true,
  },
  [anon_sym_in] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_AMP_AMP] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_and] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_xor] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_CARET_CARET] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_or] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PIPE_PIPE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LBRACE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACE] = {
    .visible = true,
    .named = false,
  },
  [sym_comment] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_eq] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ne] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lt] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_le] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_gt] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ge] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_EQ_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_contains] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_matches] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_TILDE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_concat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_COMMA] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lookup_json_string] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lower] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_regex_replace] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_remove_bytes] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_to_string] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_upper] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_url_decode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_uuidv4] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ends_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_starts_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_any] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_all] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LBRACK_STAR_RBRACK] = {
    .visible = true,
    .named = false,
  },
  [sym_number] = {
    .visible = true,
    .named = true,
  },
  [sym_string] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_true] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_false] = {
    .visible = true,
    .named = false,
  },
  [sym_ipv4] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_SLASH] = {
    .visible = true,
    .named = false,
  },
  [aux_sym_ip_range_token1] = {
    .visible = false,
    .named = false,
  },
  [sym_ip_list] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_not] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_STAR] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTasnum] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTscore] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTedge_DOTserver_port] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTthreat_score] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp_DOTtype] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp_DOTcode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOThdr_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTlen] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTopt_DOTtype] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTttl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTsrcport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTdstport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp_DOTdstport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp_DOTsrcport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTcode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOT1xxx_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTedge_DOTserver_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTdst] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTcookie] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOThost] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTreferer] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTfull_uri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTmethod] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTuser_agent] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTversion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTx_forwarded_for] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTlat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTlon] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTcity] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTpostal_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTmetro_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTcontinent] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOThostname_DOTmetadata] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTworker_DOTupstream_zone] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTcolo_DOTname] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTcolo_DOTregion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTdst_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTresponse_DOTerror_type] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTrandom_seed] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTcookies] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTclient_DOTbot] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_sip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTack] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTcwr] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTecn] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTfin] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTpush] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTreset] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTsyn] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTurg] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = {
    .visible = true,
    .named = false,
  },
  [sym_source_file] = {
    .visible = true,
    .named = true,
  },
  [sym__expression] = {
    .visible = false,
    .named = true,
  },
  [sym_not_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_in_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_compound_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_set] = {
    .visible = true,
    .named = true,
  },
  [sym_string_set] = {
    .visible = true,
    .named = true,
  },
  [sym_number_set] = {
    .visible = true,
    .named = true,
  },
  [sym_simple_expression] = {
    .visible = true,
    .named = true,
  },
  [sym__bool_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym__number_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym__string_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym_string_func] = {
    .visible = true,
    .named = true,
  },
  [sym_number_func] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_func] = {
    .visible = true,
    .named = true,
  },
  [sym_array_func] = {
    .visible = true,
    .named = true,
  },
  [sym_group] = {
    .visible = true,
    .named = true,
  },
  [sym_boolean] = {
    .visible = true,
    .named = true,
  },
  [sym__ip] = {
    .visible = false,
    .named = true,
  },
  [sym_ip_range] = {
    .visible = true,
    .named = true,
  },
  [sym_not_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_number_array] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_array] = {
    .visible = true,
    .named = true,
  },
  [sym_string_array] = {
    .visible = true,
    .named = true,
  },
  [sym__string_array_expansion] = {
    .visible = false,
    .named = true,
  },
  [sym_boollike_field] = {
    .visible = true,
    .named = true,
  },
  [sym_numberlike_field] = {
    .visible = true,
    .named = true,
  },
  [sym_stringlike_field] = {
    .visible = true,
    .named = true,
  },
  [sym_number_field] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_field] = {
    .visible = true,
    .named = true,
  },
  [sym_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_bytes_field] = {
    .visible = true,
    .named = true,
  },
  [sym_map_string_array_field] = {
    .visible = true,
    .named = true,
  },
  [sym_array_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_array_number_field] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_field] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_source_file_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_ip_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_string_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_number_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_string_func_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_string_func_repeat2] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_field = 1,
  field_func = 2,
  field_index = 3,
  field_inner = 4,
  field_ip = 5,
  field_key = 6,
  field_keys = 7,
  field_lhs = 8,
  field_mask = 9,
  field_operator = 10,
  field_regex = 11,
  field_replacement = 12,
  field_rhs = 13,
  field_seed = 14,
  field_source = 15,
  field_value = 16,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
  [field_func] = "func",
  [field_index] = "index",
  [field_inner] = "inner",
  [field_ip] = "ip",
  [field_key] = "key",
  [field_keys] = "keys",
  [field_lhs] = "lhs",
  [field_mask] = "mask",
  [field_operator] = "operator",
  [field_regex] = "regex",
  [field_replacement] = "replacement",
  [field_rhs] = "rhs",
  [field_seed] = "seed",
  [field_source] = "source",
  [field_value] = "value",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 1},
  [2] = {.index = 1, .length = 3},
  [3] = {.index = 4, .length = 3},
  [4] = {.index = 7, .length = 2},
  [5] = {.index = 9, .length = 3},
  [6] = {.index = 12, .length = 2},
  [7] = {.index = 14, .length = 1},
  [8] = {.index = 15, .length = 1},
  [9] = {.index = 16, .length = 4},
  [10] = {.index = 20, .length = 3},
  [11] = {.index = 23, .length = 3},
  [12] = {.index = 26, .length = 1},
  [13] = {.index = 27, .length = 2},
  [14] = {.index = 29, .length = 2},
  [15] = {.index = 31, .length = 4},
  [16] = {.index = 35, .length = 3},
  [17] = {.index = 38, .length = 4},
  [18] = {.index = 42, .length = 3},
  [19] = {.index = 45, .length = 5},
  [20] = {.index = 50, .length = 5},
  [21] = {.index = 55, .length = 4},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_inner, 1},
  [1] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [4] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
  [7] =
    {field_field, 2},
    {field_func, 0},
  [9] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_seed, 2},
  [12] =
    {field_func, 0},
    {field_seed, 2},
  [14] =
    {field_index, 2},
  [15] =
    {field_key, 2},
  [16] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_keys, 3},
  [20] =
    {field_field, 2},
    {field_func, 0},
    {field_keys, 3},
  [23] =
    {field_field, 2},
    {field_field, 3},
    {field_func, 0},
  [26] =
    {field_func, 0},
  [27] =
    {field_ip, 0},
    {field_mask, 2},
  [29] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
  [31] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_replacement, 4},
  [35] =
    {field_field, 2},
    {field_func, 0},
    {field_replacement, 4},
  [38] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_value, 4},
  [42] =
    {field_field, 2},
    {field_func, 0},
    {field_value, 4},
  [45] =
    {field_func, 0},
    {field_lhs, 2},
    {field_lhs, 3},
    {field_operator, 4},
    {field_rhs, 5},
  [50] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
  [55] =
    {field_func, 0},
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
};

static const TSSymbol ts_alias_sequences[PRODUCTION_ID_COUNT][MAX_ALIAS_SEQUENCE_LENGTH] = {
  [0] = {0},
};

static const uint16_t ts_non_terminal_alias_map[] = {
  0,
};

static const TSStateId ts_primary_state_ids[STATE_COUNT] = {
  [0] = 0,
  [1] = 1,
  [2] = 2,
  [3] = 3,
  [4] = 4,
  [5] = 5,
  [6] = 6,
  [7] = 7,
  [8] = 8,
  [9] = 9,
  [10] = 10,
  [11] = 11,
  [12] = 12,
  [13] = 13,
  [14] = 14,
  [15] = 15,
  [16] = 16,
  [17] = 17,
  [18] = 18,
  [19] = 19,
  [20] = 20,
  [21] = 21,
  [22] = 22,
  [23] = 23,
  [24] = 24,
  [25] = 25,
  [26] = 26,
  [27] = 27,
  [28] = 28,
  [29] = 29,
  [30] = 30,
  [31] = 31,
  [32] = 32,
  [33] = 33,
  [34] = 34,
  [35] = 35,
  [36] = 35,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 41,
  [44] = 44,
  [45] = 45,
  [46] = 46,
  [47] = 47,
  [48] = 48,
  [49] = 49,
  [50] = 50,
  [51] = 51,
  [52] = 52,
  [53] = 53,
  [54] = 54,
  [55] = 55,
  [56] = 56,
  [57] = 57,
  [58] = 55,
  [59] = 57,
  [60] = 56,
  [61] = 61,
  [62] = 61,
  [63] = 53,
  [64] = 54,
  [65] = 65,
  [66] = 66,
  [67] = 67,
  [68] = 68,
  [69] = 69,
  [70] = 70,
  [71] = 71,
  [72] = 72,
  [73] = 73,
  [74] = 74,
  [75] = 75,
  [76] = 76,
  [77] = 77,
  [78] = 78,
  [79] = 79,
  [80] = 80,
  [81] = 81,
  [82] = 81,
  [83] = 83,
  [84] = 84,
  [85] = 85,
  [86] = 86,
  [87] = 87,
  [88] = 88,
  [89] = 89,
  [90] = 90,
  [91] = 91,
  [92] = 92,
  [93] = 93,
  [94] = 94,
  [95] = 94,
  [96] = 96,
  [97] = 97,
  [98] = 98,
  [99] = 99,
  [100] = 100,
  [101] = 99,
  [102] = 102,
  [103] = 103,
  [104] = 104,
  [105] = 105,
  [106] = 106,
  [107] = 107,
  [108] = 108,
  [109] = 109,
  [110] = 110,
  [111] = 111,
  [112] = 112,
  [113] = 113,
  [114] = 114,
  [115] = 115,
  [116] = 116,
  [117] = 117,
  [118] = 118,
  [119] = 119,
  [120] = 120,
  [121] = 121,
  [122] = 122,
  [123] = 123,
  [124] = 124,
  [125] = 125,
  [126] = 126,
  [127] = 127,
  [128] = 128,
  [129] = 129,
  [130] = 130,
  [131] = 131,
  [132] = 129,
  [133] = 133,
  [134] = 134,
  [135] = 135,
  [136] = 136,
  [137] = 137,
  [138] = 138,
  [139] = 139,
  [140] = 112,
  [141] = 111,
  [142] = 142,
  [143] = 143,
  [144] = 144,
  [145] = 145,
  [146] = 146,
  [147] = 147,
  [148] = 148,
  [149] = 149,
  [150] = 150,
  [151] = 151,
  [152] = 152,
  [153] = 108,
  [154] = 154,
  [155] = 155,
  [156] = 156,
  [157] = 157,
  [158] = 158,
  [159] = 119,
  [160] = 160,
  [161] = 161,
  [162] = 162,
  [163] = 163,
  [164] = 164,
  [165] = 165,
  [166] = 122,
  [167] = 167,
  [168] = 168,
  [169] = 169,
  [170] = 170,
  [171] = 171,
  [172] = 172,
  [173] = 173,
  [174] = 174,
  [175] = 175,
  [176] = 176,
  [177] = 177,
  [178] = 178,
  [179] = 179,
  [180] = 106,
  [181] = 114,
  [182] = 182,
  [183] = 183,
  [184] = 126,
  [185] = 185,
  [186] = 186,
  [187] = 187,
  [188] = 128,
  [189] = 189,
  [190] = 113,
  [191] = 191,
  [192] = 192,
  [193] = 193,
  [194] = 194,
  [195] = 195,
  [196] = 115,
  [197] = 118,
  [198] = 116,
  [199] = 199,
  [200] = 200,
  [201] = 201,
  [202] = 202,
  [203] = 203,
  [204] = 204,
  [205] = 205,
  [206] = 206,
  [207] = 207,
  [208] = 208,
  [209] = 209,
  [210] = 210,
  [211] = 211,
  [212] = 212,
  [213] = 169,
  [214] = 206,
  [215] = 204,
  [216] = 172,
  [217] = 217,
  [218] = 218,
  [219] = 219,
  [220] = 131,
  [221] = 155,
  [222] = 222,
  [223] = 164,
  [224] = 167,
  [225] = 194,
  [226] = 157,
  [227] = 150,
  [228] = 145,
  [229] = 229,
  [230] = 230,
  [231] = 231,
  [232] = 232,
  [233] = 136,
  [234] = 143,
  [235] = 186,
  [236] = 182,
  [237] = 151,
  [238] = 147,
  [239] = 139,
  [240] = 210,
  [241] = 202,
  [242] = 242,
  [243] = 243,
  [244] = 162,
  [245] = 156,
  [246] = 148,
  [247] = 134,
  [248] = 212,
  [249] = 249,
  [250] = 149,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(950);
      if (lookahead == '!') ADVANCE(1016);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(960);
      if (lookahead == '$') ADVANCE(1011);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(978);
      if (lookahead == ')') ADVANCE(980);
      if (lookahead == '*') ADVANCE(1020);
      if (lookahead == ',') ADVANCE(979);
      if (lookahead == '/') ADVANCE(1005);
      if (lookahead == '3') ADVANCE(995);
      if (lookahead == '<') ADVANCE(970);
      if (lookahead == '=') ADVANCE(59);
      if (lookahead == '>') ADVANCE(972);
      if (lookahead == '[') ADVANCE(1018);
      if (lookahead == ']') ADVANCE(1019);
      if (lookahead == '^') ADVANCE(61);
      if (lookahead == 'a') ADVANCE(473);
      if (lookahead == 'c') ADVANCE(382);
      if (lookahead == 'e') ADVANCE(522);
      if (lookahead == 'f') ADVANCE(108);
      if (lookahead == 'g') ADVANCE(256);
      if (lookahead == 'h') ADVANCE(831);
      if (lookahead == 'i') ADVANCE(171);
      if (lookahead == 'l') ADVANCE(257);
      if (lookahead == 'm') ADVANCE(111);
      if (lookahead == 'n') ADVANCE(259);
      if (lookahead == 'o') ADVANCE(683);
      if (lookahead == 'r') ADVANCE(103);
      if (lookahead == 's') ADVANCE(422);
      if (lookahead == 't') ADVANCE(179);
      if (lookahead == 'u') ADVANCE(225);
      if (lookahead == 'x') ADVANCE(583);
      if (lookahead == '{') ADVANCE(958);
      if (lookahead == '|') ADVANCE(948);
      if (lookahead == '}') ADVANCE(959);
      if (lookahead == '~') ADVANCE(976);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(996);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(996);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(58);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(960);
      if (lookahead == ')') ADVANCE(980);
      if (lookahead == ',') ADVANCE(979);
      if (lookahead == '<') ADVANCE(970);
      if (lookahead == '=') ADVANCE(59);
      if (lookahead == '>') ADVANCE(972);
      if (lookahead == 'c') ADVANCE(384);
      if (lookahead == 'e') ADVANCE(680);
      if (lookahead == 'g') ADVANCE(256);
      if (lookahead == 'h') ADVANCE(884);
      if (lookahead == 'i') ADVANCE(197);
      if (lookahead == 'l') ADVANCE(287);
      if (lookahead == 'm') ADVANCE(111);
      if (lookahead == 'n') ADVANCE(258);
      if (lookahead == 'r') ADVANCE(103);
      if (lookahead == 't') ADVANCE(189);
      if (lookahead == 'u') ADVANCE(233);
      if (lookahead == '}') ADVANCE(959);
      if (lookahead == '~') ADVANCE(976);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(996);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(997);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(960);
      if (lookahead == '3') ADVANCE(1007);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1008);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(1006);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(952);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(164);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(181);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(176);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(562);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(126);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(142);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(51);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(394);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(248);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(393);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(517);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(55);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(55);
      if (lookahead == '5') ADVANCE(18);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(16);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(20);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(16);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(20);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(16);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(170);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(187);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(143);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(392);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(165);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(420);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(466);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(168);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(53);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(53);
      if (lookahead == '5') ADVANCE(31);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(29);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(33);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(53);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(29);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(53);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(53);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(29);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(778);
      END_STATE();
    case 35:
      if (lookahead == '.') ADVANCE(204);
      END_STATE();
    case 36:
      if (lookahead == '.') ADVANCE(875);
      END_STATE();
    case 37:
      if (lookahead == '.') ADVANCE(670);
      END_STATE();
    case 38:
      if (lookahead == '.') ADVANCE(421);
      END_STATE();
    case 39:
      if (lookahead == '.') ADVANCE(54);
      END_STATE();
    case 40:
      if (lookahead == '.') ADVANCE(54);
      if (lookahead == '5') ADVANCE(41);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(39);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(43);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(39);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(43);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(39);
      END_STATE();
    case 44:
      if (lookahead == '.') ADVANCE(893);
      END_STATE();
    case 45:
      if (lookahead == '.') ADVANCE(186);
      END_STATE();
    case 46:
      if (lookahead == '.') ADVANCE(515);
      END_STATE();
    case 47:
      if (lookahead == '.') ADVANCE(728);
      END_STATE();
    case 48:
      if (lookahead == '.') ADVANCE(331);
      END_STATE();
    case 49:
      if (lookahead == '.') ADVANCE(805);
      END_STATE();
    case 50:
      if (lookahead == '.') ADVANCE(182);
      END_STATE();
    case 51:
      if (lookahead == '1') ADVANCE(927);
      if (lookahead == 'c') ADVANCE(630);
      if (lookahead == 'h') ADVANCE(376);
      END_STATE();
    case 52:
      if (lookahead == '1') ADVANCE(83);
      if (lookahead == '2') ADVANCE(102);
      END_STATE();
    case 53:
      if (lookahead == '2') ADVANCE(1001);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(1004);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1003);
      END_STATE();
    case 54:
      if (lookahead == '2') ADVANCE(30);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(32);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 55:
      if (lookahead == '2') ADVANCE(40);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(42);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(43);
      END_STATE();
    case 56:
      if (lookahead == '3') ADVANCE(75);
      END_STATE();
    case 57:
      if (lookahead == '4') ADVANCE(988);
      END_STATE();
    case 58:
      if (lookahead == '=') ADVANCE(969);
      END_STATE();
    case 59:
      if (lookahead == '=') ADVANCE(968);
      END_STATE();
    case 60:
      if (lookahead == ']') ADVANCE(994);
      END_STATE();
    case 61:
      if (lookahead == '^') ADVANCE(955);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(465);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(166);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(438);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(52);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(736);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(500);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(921);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(385);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(946);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(779);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(229);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(185);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(486);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(417);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(119);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(488);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(661);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(450);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(299);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(712);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(898);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(444);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(791);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(896);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(900);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(452);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(255);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(924);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(391);
      END_STATE();
    case 91:
      if (lookahead == '_') ADVANCE(169);
      END_STATE();
    case 92:
      if (lookahead == '_') ADVANCE(144);
      END_STATE();
    case 93:
      if (lookahead == '_') ADVANCE(808);
      END_STATE();
    case 94:
      if (lookahead == '_') ADVANCE(207);
      END_STATE();
    case 95:
      if (lookahead == '_') ADVANCE(877);
      END_STATE();
    case 96:
      if (lookahead == '_') ADVANCE(209);
      END_STATE();
    case 97:
      if (lookahead == '_') ADVANCE(210);
      END_STATE();
    case 98:
      if (lookahead == '_') ADVANCE(211);
      END_STATE();
    case 99:
      if (lookahead == '_') ADVANCE(212);
      END_STATE();
    case 100:
      if (lookahead == '_') ADVANCE(812);
      END_STATE();
    case 101:
      if (lookahead == '_') ADVANCE(520);
      END_STATE();
    case 102:
      if (lookahead == '_') ADVANCE(464);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(920);
      if (lookahead == 'e') ADVANCE(398);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(383);
      if (lookahead == 'o') ADVANCE(691);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(56);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(56);
      if (lookahead == 's') ADVANCE(88);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(1073);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(479);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(537);
      if (lookahead == 'b') ADVANCE(598);
      if (lookahead == 'm') ADVANCE(118);
      if (lookahead == 'o') ADVANCE(658);
      if (lookahead == 'v') ADVANCE(654);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(401);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(815);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(696);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(538);
      if (lookahead == 'e') ADVANCE(781);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(433);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(506);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(919);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(504);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(480);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(899);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(817);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(191);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(180);
      if (lookahead == 'c') ADVANCE(922);
      if (lookahead == 'e') ADVANCE(188);
      if (lookahead == 'f') ADVANCE(440);
      if (lookahead == 'p') ADVANCE(891);
      if (lookahead == 'r') ADVANCE(366);
      if (lookahead == 's') ADVANCE(940);
      if (lookahead == 'u') ADVANCE(695);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(247);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(497);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(250);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(787);
      if (lookahead == 'c') ADVANCE(582);
      if (lookahead == 'i') ADVANCE(784);
      if (lookahead == 's') ADVANCE(887);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(543);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(489);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(872);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(820);
      if (lookahead == 'o') ADVANCE(528);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(742);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(782);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(542);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(737);
      if (lookahead == 'p') ADVANCE(137);
      if (lookahead == 'q') ADVANCE(906);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(806);
      END_STATE();
    case 136:
      if (lookahead == 'a') ADVANCE(849);
      END_STATE();
    case 137:
      if (lookahead == 'a') ADVANCE(843);
      END_STATE();
    case 138:
      if (lookahead == 'a') ADVANCE(845);
      END_STATE();
    case 139:
      if (lookahead == 'a') ADVANCE(503);
      END_STATE();
    case 140:
      if (lookahead == 'a') ADVANCE(405);
      END_STATE();
    case 141:
      if (lookahead == 'a') ADVANCE(507);
      END_STATE();
    case 142:
      if (lookahead == 'a') ADVANCE(198);
      if (lookahead == 'b') ADVANCE(596);
      if (lookahead == 'c') ADVANCE(639);
      if (lookahead == 'f') ADVANCE(890);
      if (lookahead == 'h') ADVANCE(360);
      if (lookahead == 'm') ADVANCE(346);
      if (lookahead == 't') ADVANCE(455);
      if (lookahead == 'u') ADVANCE(703);
      if (lookahead == 'v') ADVANCE(337);
      END_STATE();
    case 143:
      if (lookahead == 'a') ADVANCE(198);
      if (lookahead == 'b') ADVANCE(638);
      if (lookahead == 'c') ADVANCE(639);
      if (lookahead == 'f') ADVANCE(890);
      if (lookahead == 'h') ADVANCE(378);
      if (lookahead == 'm') ADVANCE(346);
      if (lookahead == 'u') ADVANCE(703);
      if (lookahead == 'v') ADVANCE(337);
      END_STATE();
    case 144:
      if (lookahead == 'a') ADVANCE(407);
      END_STATE();
    case 145:
      if (lookahead == 'a') ADVANCE(722);
      END_STATE();
    case 146:
      if (lookahead == 'a') ADVANCE(406);
      END_STATE();
    case 147:
      if (lookahead == 'a') ADVANCE(552);
      END_STATE();
    case 148:
      if (lookahead == 'a') ADVANCE(868);
      END_STATE();
    case 149:
      if (lookahead == 'a') ADVANCE(869);
      END_STATE();
    case 150:
      if (lookahead == 'a') ADVANCE(509);
      END_STATE();
    case 151:
      if (lookahead == 'a') ADVANCE(510);
      END_STATE();
    case 152:
      if (lookahead == 'a') ADVANCE(511);
      END_STATE();
    case 153:
      if (lookahead == 'a') ADVANCE(512);
      END_STATE();
    case 154:
      if (lookahead == 'a') ADVANCE(513);
      END_STATE();
    case 155:
      if (lookahead == 'a') ADVANCE(251);
      END_STATE();
    case 156:
      if (lookahead == 'a') ADVANCE(490);
      END_STATE();
    case 157:
      if (lookahead == 'a') ADVANCE(741);
      if (lookahead == 'p') ADVANCE(138);
      if (lookahead == 'q') ADVANCE(907);
      END_STATE();
    case 158:
      if (lookahead == 'a') ADVANCE(252);
      END_STATE();
    case 159:
      if (lookahead == 'a') ADVANCE(491);
      END_STATE();
    case 160:
      if (lookahead == 'a') ADVANCE(492);
      END_STATE();
    case 161:
      if (lookahead == 'a') ADVANCE(493);
      END_STATE();
    case 162:
      if (lookahead == 'a') ADVANCE(408);
      END_STATE();
    case 163:
      if (lookahead == 'a') ADVANCE(578);
      END_STATE();
    case 164:
      if (lookahead == 'b') ADVANCE(594);
      if (lookahead == 'c') ADVANCE(478);
      if (lookahead == 'e') ADVANCE(216);
      if (lookahead == 'h') ADVANCE(617);
      if (lookahead == 'r') ADVANCE(113);
      if (lookahead == 't') ADVANCE(415);
      if (lookahead == 'w') ADVANCE(104);
      END_STATE();
    case 165:
      if (lookahead == 'b') ADVANCE(594);
      if (lookahead == 'c') ADVANCE(478);
      if (lookahead == 'e') ADVANCE(216);
      if (lookahead == 'h') ADVANCE(617);
      if (lookahead == 'r') ADVANCE(289);
      if (lookahead == 't') ADVANCE(415);
      if (lookahead == 'w') ADVANCE(104);
      END_STATE();
    case 166:
      if (lookahead == 'b') ADVANCE(939);
      END_STATE();
    case 167:
      if (lookahead == 'b') ADVANCE(227);
      END_STATE();
    case 168:
      if (lookahead == 'b') ADVANCE(607);
      END_STATE();
    case 169:
      if (lookahead == 'b') ADVANCE(612);
      END_STATE();
    case 170:
      if (lookahead == 'b') ADVANCE(644);
      if (lookahead == 'c') ADVANCE(589);
      if (lookahead == 'h') ADVANCE(617);
      if (lookahead == 'r') ADVANCE(289);
      if (lookahead == 'w') ADVANCE(595);
      END_STATE();
    case 171:
      if (lookahead == 'c') ADVANCE(501);
      if (lookahead == 'n') ADVANCE(951);
      if (lookahead == 'p') ADVANCE(1079);
      END_STATE();
    case 172:
      if (lookahead == 'c') ADVANCE(501);
      if (lookahead == 'p') ADVANCE(1079);
      END_STATE();
    case 173:
      if (lookahead == 'c') ADVANCE(416);
      END_STATE();
    case 174:
      if (lookahead == 'c') ADVANCE(1045);
      END_STATE();
    case 175:
      if (lookahead == 'c') ADVANCE(1009);
      END_STATE();
    case 176:
      if (lookahead == 'c') ADVANCE(439);
      if (lookahead == 'l') ADVANCE(130);
      if (lookahead == 'm') ADVANCE(357);
      if (lookahead == 'p') ADVANCE(625);
      END_STATE();
    case 177:
      if (lookahead == 'c') ADVANCE(1021);
      END_STATE();
    case 178:
      if (lookahead == 'c') ADVANCE(1022);
      END_STATE();
    case 179:
      if (lookahead == 'c') ADVANCE(646);
      if (lookahead == 'o') ADVANCE(71);
      if (lookahead == 'r') ADVANCE(886);
      END_STATE();
    case 180:
      if (lookahead == 'c') ADVANCE(467);
      END_STATE();
    case 181:
      if (lookahead == 'c') ADVANCE(597);
      if (lookahead == 'h') ADVANCE(622);
      if (lookahead == 'r') ADVANCE(264);
      if (lookahead == 'u') ADVANCE(803);
      if (lookahead == 'x') ADVANCE(69);
      END_STATE();
    case 182:
      if (lookahead == 'c') ADVANCE(597);
      if (lookahead == 'h') ADVANCE(622);
      if (lookahead == 'r') ADVANCE(379);
      if (lookahead == 'u') ADVANCE(803);
      if (lookahead == 'x') ADVANCE(69);
      END_STATE();
    case 183:
      if (lookahead == 'c') ADVANCE(175);
      END_STATE();
    case 184:
      if (lookahead == 'c') ADVANCE(614);
      if (lookahead == 't') ADVANCE(942);
      END_STATE();
    case 185:
      if (lookahead == 'c') ADVANCE(494);
      END_STATE();
    case 186:
      if (lookahead == 'c') ADVANCE(586);
      END_STATE();
    case 187:
      if (lookahead == 'c') ADVANCE(582);
      if (lookahead == 's') ADVANCE(887);
      END_STATE();
    case 188:
      if (lookahead == 'c') ADVANCE(529);
      END_STATE();
    case 189:
      if (lookahead == 'c') ADVANCE(650);
      if (lookahead == 'o') ADVANCE(71);
      END_STATE();
    case 190:
      if (lookahead == 'c') ADVANCE(7);
      END_STATE();
    case 191:
      if (lookahead == 'c') ADVANCE(273);
      END_STATE();
    case 192:
      if (lookahead == 'c') ADVANCE(275);
      END_STATE();
    case 193:
      if (lookahead == 'c') ADVANCE(879);
      END_STATE();
    case 194:
      if (lookahead == 'c') ADVANCE(358);
      END_STATE();
    case 195:
      if (lookahead == 'c') ADVANCE(120);
      END_STATE();
    case 196:
      if (lookahead == 'c') ADVANCE(120);
      if (lookahead == 't') ADVANCE(114);
      END_STATE();
    case 197:
      if (lookahead == 'c') ADVANCE(505);
      if (lookahead == 'n') ADVANCE(951);
      if (lookahead == 'p') ADVANCE(1080);
      END_STATE();
    case 198:
      if (lookahead == 'c') ADVANCE(194);
      END_STATE();
    case 199:
      if (lookahead == 'c') ADVANCE(627);
      END_STATE();
    case 200:
      if (lookahead == 'c') ADVANCE(148);
      END_STATE();
    case 201:
      if (lookahead == 'c') ADVANCE(631);
      END_STATE();
    case 202:
      if (lookahead == 'c') ADVANCE(149);
      END_STATE();
    case 203:
      if (lookahead == 'c') ADVANCE(633);
      END_STATE();
    case 204:
      if (lookahead == 'c') ADVANCE(370);
      END_STATE();
    case 205:
      if (lookahead == 'c') ADVANCE(618);
      END_STATE();
    case 206:
      if (lookahead == 'c') ADVANCE(673);
      END_STATE();
    case 207:
      if (lookahead == 'c') ADVANCE(626);
      END_STATE();
    case 208:
      if (lookahead == 'c') ADVANCE(675);
      END_STATE();
    case 209:
      if (lookahead == 'c') ADVANCE(632);
      END_STATE();
    case 210:
      if (lookahead == 'c') ADVANCE(634);
      END_STATE();
    case 211:
      if (lookahead == 'c') ADVANCE(635);
      END_STATE();
    case 212:
      if (lookahead == 'c') ADVANCE(636);
      END_STATE();
    case 213:
      if (lookahead == 'c') ADVANCE(880);
      END_STATE();
    case 214:
      if (lookahead == 'd') ADVANCE(953);
      if (lookahead == 'y') ADVANCE(992);
      END_STATE();
    case 215:
      if (lookahead == 'd') ADVANCE(774);
      END_STATE();
    case 216:
      if (lookahead == 'd') ADVANCE(402);
      END_STATE();
    case 217:
      if (lookahead == 'd') ADVANCE(1090);
      END_STATE();
    case 218:
      if (lookahead == 'd') ADVANCE(1052);
      END_STATE();
    case 219:
      if (lookahead == 'd') ADVANCE(1127);
      END_STATE();
    case 220:
      if (lookahead == 'd') ADVANCE(1126);
      END_STATE();
    case 221:
      if (lookahead == 'd') ADVANCE(1115);
      END_STATE();
    case 222:
      if (lookahead == 'd') ADVANCE(1116);
      END_STATE();
    case 223:
      if (lookahead == 'd') ADVANCE(1113);
      END_STATE();
    case 224:
      if (lookahead == 'd') ADVANCE(914);
      END_STATE();
    case 225:
      if (lookahead == 'd') ADVANCE(647);
      if (lookahead == 'p') ADVANCE(668);
      if (lookahead == 'r') ADVANCE(477);
      if (lookahead == 'u') ADVANCE(429);
      END_STATE();
    case 226:
      if (lookahead == 'd') ADVANCE(800);
      if (lookahead == 'f') ADVANCE(481);
      if (lookahead == 's') ADVANCE(693);
      END_STATE();
    case 227:
      if (lookahead == 'd') ADVANCE(432);
      END_STATE();
    case 228:
      if (lookahead == 'd') ADVANCE(700);
      END_STATE();
    case 229:
      if (lookahead == 'd') ADVANCE(290);
      END_STATE();
    case 230:
      if (lookahead == 'd') ADVANCE(938);
      END_STATE();
    case 231:
      if (lookahead == 'd') ADVANCE(585);
      END_STATE();
    case 232:
      if (lookahead == 'd') ADVANCE(265);
      END_STATE();
    case 233:
      if (lookahead == 'd') ADVANCE(651);
      if (lookahead == 'p') ADVANCE(668);
      if (lookahead == 'r') ADVANCE(477);
      if (lookahead == 'u') ADVANCE(429);
      END_STATE();
    case 234:
      if (lookahead == 'd') ADVANCE(267);
      END_STATE();
    case 235:
      if (lookahead == 'd') ADVANCE(91);
      END_STATE();
    case 236:
      if (lookahead == 'd') ADVANCE(769);
      END_STATE();
    case 237:
      if (lookahead == 'd') ADVANCE(301);
      END_STATE();
    case 238:
      if (lookahead == 'd') ADVANCE(276);
      END_STATE();
    case 239:
      if (lookahead == 'd') ADVANCE(277);
      END_STATE();
    case 240:
      if (lookahead == 'd') ADVANCE(278);
      END_STATE();
    case 241:
      if (lookahead == 'd') ADVANCE(284);
      END_STATE();
    case 242:
      if (lookahead == 'd') ADVANCE(285);
      END_STATE();
    case 243:
      if (lookahead == 'd') ADVANCE(286);
      END_STATE();
    case 244:
      if (lookahead == 'd') ADVANCE(780);
      if (lookahead == 'g') ADVANCE(293);
      if (lookahead == 'h') ADVANCE(228);
      if (lookahead == 'l') ADVANCE(288);
      if (lookahead == 'o') ADVANCE(659);
      if (lookahead == 's') ADVANCE(692);
      if (lookahead == 't') ADVANCE(838);
      END_STATE();
    case 245:
      if (lookahead == 'd') ADVANCE(77);
      END_STATE();
    case 246:
      if (lookahead == 'd') ADVANCE(941);
      END_STATE();
    case 247:
      if (lookahead == 'd') ADVANCE(136);
      END_STATE();
    case 248:
      if (lookahead == 'd') ADVANCE(363);
      if (lookahead == 'j') ADVANCE(106);
      if (lookahead == 's') ADVANCE(203);
      if (lookahead == 'v') ADVANCE(351);
      END_STATE();
    case 249:
      if (lookahead == 'd') ADVANCE(795);
      if (lookahead == 'g') ADVANCE(374);
      if (lookahead == 's') ADVANCE(716);
      END_STATE();
    case 250:
      if (lookahead == 'd') ADVANCE(343);
      END_STATE();
    case 251:
      if (lookahead == 'd') ADVANCE(350);
      END_STATE();
    case 252:
      if (lookahead == 'd') ADVANCE(354);
      END_STATE();
    case 253:
      if (lookahead == 'd') ADVANCE(90);
      END_STATE();
    case 254:
      if (lookahead == 'd') ADVANCE(810);
      if (lookahead == 's') ADVANCE(749);
      END_STATE();
    case 255:
      if (lookahead == 'd') ADVANCE(381);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(967);
      if (lookahead == 't') ADVANCE(966);
      END_STATE();
    case 257:
      if (lookahead == 'e') ADVANCE(965);
      if (lookahead == 'o') ADVANCE(580);
      if (lookahead == 't') ADVANCE(963);
      END_STATE();
    case 258:
      if (lookahead == 'e') ADVANCE(962);
      END_STATE();
    case 259:
      if (lookahead == 'e') ADVANCE(962);
      if (lookahead == 'o') ADVANCE(816);
      END_STATE();
    case 260:
      if (lookahead == 'e') ADVANCE(926);
      END_STATE();
    case 261:
      if (lookahead == 'e') ADVANCE(998);
      END_STATE();
    case 262:
      if (lookahead == 'e') ADVANCE(999);
      END_STATE();
    case 263:
      if (lookahead == 'e') ADVANCE(1009);
      END_STATE();
    case 264:
      if (lookahead == 'e') ADVANCE(387);
      END_STATE();
    case 265:
      if (lookahead == 'e') ADVANCE(1032);
      END_STATE();
    case 266:
      if (lookahead == 'e') ADVANCE(1031);
      END_STATE();
    case 267:
      if (lookahead == 'e') ADVANCE(987);
      END_STATE();
    case 268:
      if (lookahead == 'e') ADVANCE(1048);
      END_STATE();
    case 269:
      if (lookahead == 'e') ADVANCE(1035);
      END_STATE();
    case 270:
      if (lookahead == 'e') ADVANCE(682);
      END_STATE();
    case 271:
      if (lookahead == 'e') ADVANCE(1075);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(1027);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(983);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(1026);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(1030);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(1063);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(1043);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(1062);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(1089);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(1088);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(1042);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(1024);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(1074);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(1044);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(1066);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(1067);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(964);
      if (lookahead == 'o') ADVANCE(580);
      if (lookahead == 't') ADVANCE(963);
      END_STATE();
    case 288:
      if (lookahead == 'e') ADVANCE(525);
      END_STATE();
    case 289:
      if (lookahead == 'e') ADVANCE(781);
      END_STATE();
    case 290:
      if (lookahead == 'e') ADVANCE(205);
      END_STATE();
    case 291:
      if (lookahead == 'e') ADVANCE(399);
      END_STATE();
    case 292:
      if (lookahead == 'e') ADVANCE(685);
      END_STATE();
    case 293:
      if (lookahead == 'e') ADVANCE(590);
      END_STATE();
    case 294:
      if (lookahead == 'e') ADVANCE(917);
      END_STATE();
    case 295:
      if (lookahead == 'e') ADVANCE(686);
      END_STATE();
    case 296:
      if (lookahead == 'e') ADVANCE(751);
      END_STATE();
    case 297:
      if (lookahead == 'e') ADVANCE(217);
      END_STATE();
    case 298:
      if (lookahead == 'e') ADVANCE(545);
      END_STATE();
    case 299:
      if (lookahead == 'e') ADVANCE(897);
      END_STATE();
    case 300:
      if (lookahead == 'e') ADVANCE(547);
      END_STATE();
    case 301:
      if (lookahead == 'e') ADVANCE(253);
      END_STATE();
    case 302:
      if (lookahead == 'e') ADVANCE(63);
      END_STATE();
    case 303:
      if (lookahead == 'e') ADVANCE(46);
      END_STATE();
    case 304:
      if (lookahead == 'e') ADVANCE(117);
      END_STATE();
    case 305:
      if (lookahead == 'e') ADVANCE(702);
      END_STATE();
    case 306:
      if (lookahead == 'e') ADVANCE(48);
      END_STATE();
    case 307:
      if (lookahead == 'e') ADVANCE(706);
      END_STATE();
    case 308:
      if (lookahead == 'e') ADVANCE(754);
      END_STATE();
    case 309:
      if (lookahead == 'e') ADVANCE(193);
      END_STATE();
    case 310:
      if (lookahead == 'e') ADVANCE(744);
      END_STATE();
    case 311:
      if (lookahead == 'e') ADVANCE(11);
      END_STATE();
    case 312:
      if (lookahead == 'e') ADVANCE(245);
      END_STATE();
    case 313:
      if (lookahead == 'e') ADVANCE(527);
      END_STATE();
    case 314:
      if (lookahead == 'e') ADVANCE(235);
      END_STATE();
    case 315:
      if (lookahead == 'e') ADVANCE(660);
      END_STATE();
    case 316:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 317:
      if (lookahead == 'e') ADVANCE(219);
      END_STATE();
    case 318:
      if (lookahead == 'e') ADVANCE(750);
      END_STATE();
    case 319:
      if (lookahead == 'e') ADVANCE(178);
      END_STATE();
    case 320:
      if (lookahead == 'e') ADVANCE(694);
      END_STATE();
    case 321:
      if (lookahead == 'e') ADVANCE(220);
      END_STATE();
    case 322:
      if (lookahead == 'e') ADVANCE(221);
      END_STATE();
    case 323:
      if (lookahead == 'e') ADVANCE(840);
      END_STATE();
    case 324:
      if (lookahead == 'e') ADVANCE(688);
      END_STATE();
    case 325:
      if (lookahead == 'e') ADVANCE(222);
      END_STATE();
    case 326:
      if (lookahead == 'e') ADVANCE(756);
      END_STATE();
    case 327:
      if (lookahead == 'e') ADVANCE(223);
      END_STATE();
    case 328:
      if (lookahead == 'e') ADVANCE(687);
      END_STATE();
    case 329:
      if (lookahead == 'e') ADVANCE(713);
      END_STATE();
    case 330:
      if (lookahead == 'e') ADVANCE(761);
      END_STATE();
    case 331:
      if (lookahead == 'e') ADVANCE(727);
      END_STATE();
    case 332:
      if (lookahead == 'e') ADVANCE(762);
      END_STATE();
    case 333:
      if (lookahead == 'e') ADVANCE(38);
      END_STATE();
    case 334:
      if (lookahead == 'e') ADVANCE(763);
      END_STATE();
    case 335:
      if (lookahead == 'e') ADVANCE(764);
      END_STATE();
    case 336:
      if (lookahead == 'e') ADVANCE(765);
      END_STATE();
    case 337:
      if (lookahead == 'e') ADVANCE(719);
      END_STATE();
    case 338:
      if (lookahead == 'e') ADVANCE(766);
      END_STATE();
    case 339:
      if (lookahead == 'e') ADVANCE(524);
      if (lookahead == 'o') ADVANCE(580);
      END_STATE();
    case 340:
      if (lookahead == 'e') ADVANCE(767);
      END_STATE();
    case 341:
      if (lookahead == 'e') ADVANCE(846);
      END_STATE();
    case 342:
      if (lookahead == 'e') ADVANCE(768);
      END_STATE();
    case 343:
      if (lookahead == 'e') ADVANCE(720);
      END_STATE();
    case 344:
      if (lookahead == 'e') ADVANCE(827);
      END_STATE();
    case 345:
      if (lookahead == 'e') ADVANCE(770);
      END_STATE();
    case 346:
      if (lookahead == 'e') ADVANCE(839);
      END_STATE();
    case 347:
      if (lookahead == 'e') ADVANCE(771);
      END_STATE();
    case 348:
      if (lookahead == 'e') ADVANCE(297);
      END_STATE();
    case 349:
      if (lookahead == 'e') ADVANCE(772);
      END_STATE();
    case 350:
      if (lookahead == 'e') ADVANCE(721);
      END_STATE();
    case 351:
      if (lookahead == 'e') ADVANCE(714);
      END_STATE();
    case 352:
      if (lookahead == 'e') ADVANCE(704);
      END_STATE();
    case 353:
      if (lookahead == 'e') ADVANCE(705);
      END_STATE();
    case 354:
      if (lookahead == 'e') ADVANCE(730);
      END_STATE();
    case 355:
      if (lookahead == 'e') ADVANCE(49);
      END_STATE();
    case 356:
      if (lookahead == 'e') ADVANCE(147);
      END_STATE();
    case 357:
      if (lookahead == 'e') ADVANCE(857);
      END_STATE();
    case 358:
      if (lookahead == 'e') ADVANCE(671);
      END_STATE();
    case 359:
      if (lookahead == 'e') ADVANCE(554);
      END_STATE();
    case 360:
      if (lookahead == 'e') ADVANCE(125);
      END_STATE();
    case 361:
      if (lookahead == 'e') ADVANCE(129);
      END_STATE();
    case 362:
      if (lookahead == 'e') ADVANCE(556);
      END_STATE();
    case 363:
      if (lookahead == 'e') ADVANCE(867);
      END_STATE();
    case 364:
      if (lookahead == 'e') ADVANCE(516);
      END_STATE();
    case 365:
      if (lookahead == 'e') ADVANCE(557);
      END_STATE();
    case 366:
      if (lookahead == 'e') ADVANCE(802);
      END_STATE();
    case 367:
      if (lookahead == 'e') ADVANCE(558);
      END_STATE();
    case 368:
      if (lookahead == 'e') ADVANCE(790);
      END_STATE();
    case 369:
      if (lookahead == 'e') ADVANCE(559);
      END_STATE();
    case 370:
      if (lookahead == 'e') ADVANCE(734);
      END_STATE();
    case 371:
      if (lookahead == 'e') ADVANCE(792);
      END_STATE();
    case 372:
      if (lookahead == 'e') ADVANCE(794);
      END_STATE();
    case 373:
      if (lookahead == 'e') ADVANCE(796);
      END_STATE();
    case 374:
      if (lookahead == 'e') ADVANCE(615);
      END_STATE();
    case 375:
      if (lookahead == 'e') ADVANCE(747);
      END_STATE();
    case 376:
      if (lookahead == 'e') ADVANCE(155);
      END_STATE();
    case 377:
      if (lookahead == 'e') ADVANCE(518);
      END_STATE();
    case 378:
      if (lookahead == 'e') ADVANCE(158);
      END_STATE();
    case 379:
      if (lookahead == 'e') ADVANCE(388);
      END_STATE();
    case 380:
      if (lookahead == 'e') ADVANCE(213);
      END_STATE();
    case 381:
      if (lookahead == 'e') ADVANCE(883);
      END_STATE();
    case 382:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(523);
      END_STATE();
    case 383:
      if (lookahead == 'f') ADVANCE(34);
      END_STATE();
    case 384:
      if (lookahead == 'f') ADVANCE(21);
      if (lookahead == 'o') ADVANCE(523);
      END_STATE();
    case 385:
      if (lookahead == 'f') ADVANCE(602);
      END_STATE();
    case 386:
      if (lookahead == 'f') ADVANCE(25);
      if (lookahead == 'o') ADVANCE(573);
      END_STATE();
    case 387:
      if (lookahead == 'f') ADVANCE(310);
      if (lookahead == 'q') ADVANCE(894);
      if (lookahead == 's') ADVANCE(677);
      END_STATE();
    case 388:
      if (lookahead == 'f') ADVANCE(310);
      if (lookahead == 'q') ADVANCE(912);
      if (lookahead == 's') ADVANCE(678);
      END_STATE();
    case 389:
      if (lookahead == 'f') ADVANCE(448);
      END_STATE();
    case 390:
      if (lookahead == 'f') ADVANCE(449);
      END_STATE();
    case 391:
      if (lookahead == 'f') ADVANCE(610);
      END_STATE();
    case 392:
      if (lookahead == 'f') ADVANCE(611);
      if (lookahead == 'm') ADVANCE(457);
      if (lookahead == 'r') ADVANCE(116);
      END_STATE();
    case 393:
      if (lookahead == 'f') ADVANCE(611);
      if (lookahead == 'm') ADVANCE(457);
      if (lookahead == 'r') ADVANCE(116);
      if (lookahead == 's') ADVANCE(431);
      if (lookahead == 't') ADVANCE(738);
      END_STATE();
    case 394:
      if (lookahead == 'f') ADVANCE(913);
      if (lookahead == 'u') ADVANCE(709);
      END_STATE();
    case 395:
      if (lookahead == 'g') ADVANCE(985);
      END_STATE();
    case 396:
      if (lookahead == 'g') ADVANCE(1125);
      END_STATE();
    case 397:
      if (lookahead == 'g') ADVANCE(981);
      END_STATE();
    case 398:
      if (lookahead == 'g') ADVANCE(260);
      if (lookahead == 'm') ADVANCE(581);
      END_STATE();
    case 399:
      if (lookahead == 'g') ADVANCE(454);
      END_STATE();
    case 400:
      if (lookahead == 'g') ADVANCE(911);
      END_STATE();
    case 401:
      if (lookahead == 'g') ADVANCE(753);
      END_STATE();
    case 402:
      if (lookahead == 'g') ADVANCE(355);
      END_STATE();
    case 403:
      if (lookahead == 'g') ADVANCE(758);
      END_STATE();
    case 404:
      if (lookahead == 'g') ADVANCE(760);
      END_STATE();
    case 405:
      if (lookahead == 'g') ADVANCE(364);
      END_STATE();
    case 406:
      if (lookahead == 'g') ADVANCE(345);
      END_STATE();
    case 407:
      if (lookahead == 'g') ADVANCE(362);
      END_STATE();
    case 408:
      if (lookahead == 'g') ADVANCE(377);
      END_STATE();
    case 409:
      if (lookahead == 'h') ADVANCE(990);
      END_STATE();
    case 410:
      if (lookahead == 'h') ADVANCE(991);
      END_STATE();
    case 411:
      if (lookahead == 'h') ADVANCE(1122);
      END_STATE();
    case 412:
      if (lookahead == 'h') ADVANCE(1054);
      END_STATE();
    case 413:
      if (lookahead == 'h') ADVANCE(1070);
      END_STATE();
    case 414:
      if (lookahead == 'h') ADVANCE(1072);
      END_STATE();
    case 415:
      if (lookahead == 'h') ADVANCE(707);
      if (lookahead == 'l') ADVANCE(777);
      END_STATE();
    case 416:
      if (lookahead == 'h') ADVANCE(296);
      END_STATE();
    case 417:
      if (lookahead == 'h') ADVANCE(132);
      END_STATE();
    case 418:
      if (lookahead == 'h') ADVANCE(600);
      END_STATE();
    case 419:
      if (lookahead == 'h') ADVANCE(35);
      END_STATE();
    case 420:
      if (lookahead == 'h') ADVANCE(870);
      END_STATE();
    case 421:
      if (lookahead == 'h') ADVANCE(376);
      END_STATE();
    case 422:
      if (lookahead == 'i') ADVANCE(645);
      if (lookahead == 's') ADVANCE(475);
      if (lookahead == 't') ADVANCE(112);
      END_STATE();
    case 423:
      if (lookahead == 'i') ADVANCE(947);
      END_STATE();
    case 424:
      if (lookahead == 'i') ADVANCE(1053);
      END_STATE();
    case 425:
      if (lookahead == 'i') ADVANCE(1028);
      END_STATE();
    case 426:
      if (lookahead == 'i') ADVANCE(1069);
      END_STATE();
    case 427:
      if (lookahead == 'i') ADVANCE(1051);
      END_STATE();
    case 428:
      if (lookahead == 'i') ADVANCE(1068);
      END_STATE();
    case 429:
      if (lookahead == 'i') ADVANCE(224);
      END_STATE();
    case 430:
      if (lookahead == 'i') ADVANCE(389);
      END_STATE();
    case 431:
      if (lookahead == 'i') ADVANCE(945);
      END_STATE();
    case 432:
      if (lookahead == 'i') ADVANCE(916);
      END_STATE();
    case 433:
      if (lookahead == 'i') ADVANCE(544);
      END_STATE();
    case 434:
      if (lookahead == 'i') ADVANCE(300);
      END_STATE();
    case 435:
      if (lookahead == 'i') ADVANCE(536);
      END_STATE();
    case 436:
      if (lookahead == 'i') ADVANCE(655);
      END_STATE();
    case 437:
      if (lookahead == 'i') ADVANCE(832);
      END_STATE();
    case 438:
      if (lookahead == 'i') ADVANCE(649);
      if (lookahead == 'p') ADVANCE(629);
      END_STATE();
    case 439:
      if (lookahead == 'i') ADVANCE(834);
      if (lookahead == 'o') ADVANCE(908);
      END_STATE();
    case 440:
      if (lookahead == 'i') ADVANCE(530);
      END_STATE();
    case 441:
      if (lookahead == 'i') ADVANCE(833);
      END_STATE();
    case 442:
      if (lookahead == 'i') ADVANCE(540);
      END_STATE();
    case 443:
      if (lookahead == 'i') ADVANCE(664);
      END_STATE();
    case 444:
      if (lookahead == 'i') ADVANCE(813);
      END_STATE();
    case 445:
      if (lookahead == 'i') ADVANCE(268);
      END_STATE();
    case 446:
      if (lookahead == 'i') ADVANCE(318);
      END_STATE();
    case 447:
      if (lookahead == 'i') ADVANCE(326);
      END_STATE();
    case 448:
      if (lookahead == 'i') ADVANCE(314);
      END_STATE();
    case 449:
      if (lookahead == 'i') ADVANCE(325);
      END_STATE();
    case 450:
      if (lookahead == 'i') ADVANCE(236);
      END_STATE();
    case 451:
      if (lookahead == 'i') ADVANCE(568);
      END_STATE();
    case 452:
      if (lookahead == 'i') ADVANCE(549);
      END_STATE();
    case 453:
      if (lookahead == 'i') ADVANCE(359);
      END_STATE();
    case 454:
      if (lookahead == 'i') ADVANCE(604);
      END_STATE();
    case 455:
      if (lookahead == 'i') ADVANCE(519);
      END_STATE();
    case 456:
      if (lookahead == 'i') ADVANCE(605);
      END_STATE();
    case 457:
      if (lookahead == 'i') ADVANCE(508);
      END_STATE();
    case 458:
      if (lookahead == 'i') ADVANCE(620);
      END_STATE();
    case 459:
      if (lookahead == 'i') ADVANCE(628);
      END_STATE();
    case 460:
      if (lookahead == 'i') ADVANCE(606);
      END_STATE();
    case 461:
      if (lookahead == 'i') ADVANCE(608);
      END_STATE();
    case 462:
      if (lookahead == 'i') ADVANCE(390);
      END_STATE();
    case 463:
      if (lookahead == 'i') ADVANCE(811);
      END_STATE();
    case 464:
      if (lookahead == 'i') ADVANCE(814);
      END_STATE();
    case 465:
      if (lookahead == 'j') ADVANCE(801);
      END_STATE();
    case 466:
      if (lookahead == 'j') ADVANCE(105);
      END_STATE();
    case 467:
      if (lookahead == 'k') ADVANCE(1118);
      END_STATE();
    case 468:
      if (lookahead == 'k') ADVANCE(889);
      END_STATE();
    case 469:
      if (lookahead == 'k') ADVANCE(322);
      END_STATE();
    case 470:
      if (lookahead == 'k') ADVANCE(445);
      END_STATE();
    case 471:
      if (lookahead == 'k') ADVANCE(305);
      END_STATE();
    case 472:
      if (lookahead == 'k') ADVANCE(447);
      END_STATE();
    case 473:
      if (lookahead == 'l') ADVANCE(474);
      if (lookahead == 'n') ADVANCE(214);
      END_STATE();
    case 474:
      if (lookahead == 'l') ADVANCE(993);
      END_STATE();
    case 475:
      if (lookahead == 'l') ADVANCE(1111);
      END_STATE();
    case 476:
      if (lookahead == 'l') ADVANCE(1036);
      END_STATE();
    case 477:
      if (lookahead == 'l') ADVANCE(72);
      END_STATE();
    case 478:
      if (lookahead == 'l') ADVANCE(434);
      if (lookahead == 'o') ADVANCE(482);
      END_STATE();
    case 479:
      if (lookahead == 'l') ADVANCE(775);
      END_STATE();
    case 480:
      if (lookahead == 'l') ADVANCE(923);
      END_STATE();
    case 481:
      if (lookahead == 'l') ADVANCE(110);
      END_STATE();
    case 482:
      if (lookahead == 'l') ADVANCE(592);
      END_STATE();
    case 483:
      if (lookahead == 'l') ADVANCE(121);
      END_STATE();
    case 484:
      if (lookahead == 'l') ADVANCE(425);
      END_STATE();
    case 485:
      if (lookahead == 'l') ADVANCE(82);
      END_STATE();
    case 486:
      if (lookahead == 'l') ADVANCE(313);
      END_STATE();
    case 487:
      if (lookahead == 'l') ADVANCE(485);
      END_STATE();
    case 488:
      if (lookahead == 'l') ADVANCE(133);
      END_STATE();
    case 489:
      if (lookahead == 'l') ADVANCE(901);
      END_STATE();
    case 490:
      if (lookahead == 'l') ADVANCE(902);
      END_STATE();
    case 491:
      if (lookahead == 'l') ADVANCE(903);
      END_STATE();
    case 492:
      if (lookahead == 'l') ADVANCE(904);
      END_STATE();
    case 493:
      if (lookahead == 'l') ADVANCE(905);
      END_STATE();
    case 494:
      if (lookahead == 'l') ADVANCE(453);
      END_STATE();
    case 495:
      if (lookahead == 'l') ADVANCE(86);
      END_STATE();
    case 496:
      if (lookahead == 'l') ADVANCE(495);
      END_STATE();
    case 497:
      if (lookahead == 'l') ADVANCE(96);
      END_STATE();
    case 498:
      if (lookahead == 'm') ADVANCE(1023);
      END_STATE();
    case 499:
      if (lookahead == 'm') ADVANCE(1096);
      END_STATE();
    case 500:
      if (lookahead == 'm') ADVANCE(127);
      END_STATE();
    case 501:
      if (lookahead == 'm') ADVANCE(648);
      END_STATE();
    case 502:
      if (lookahead == 'm') ADVANCE(423);
      END_STATE();
    case 503:
      if (lookahead == 'm') ADVANCE(663);
      END_STATE();
    case 504:
      if (lookahead == 'm') ADVANCE(70);
      END_STATE();
    case 505:
      if (lookahead == 'm') ADVANCE(652);
      END_STATE();
    case 506:
      if (lookahead == 'm') ADVANCE(303);
      END_STATE();
    case 507:
      if (lookahead == 'm') ADVANCE(271);
      END_STATE();
    case 508:
      if (lookahead == 'm') ADVANCE(280);
      END_STATE();
    case 509:
      if (lookahead == 'm') ADVANCE(330);
      END_STATE();
    case 510:
      if (lookahead == 'm') ADVANCE(334);
      END_STATE();
    case 511:
      if (lookahead == 'm') ADVANCE(335);
      END_STATE();
    case 512:
      if (lookahead == 'm') ADVANCE(336);
      END_STATE();
    case 513:
      if (lookahead == 'm') ADVANCE(347);
      END_STATE();
    case 514:
      if (lookahead == 'm') ADVANCE(84);
      END_STATE();
    case 515:
      if (lookahead == 'm') ADVANCE(341);
      END_STATE();
    case 516:
      if (lookahead == 'm') ADVANCE(365);
      END_STATE();
    case 517:
      if (lookahead == 'm') ADVANCE(797);
      if (lookahead == 's') ADVANCE(316);
      END_STATE();
    case 518:
      if (lookahead == 'm') ADVANCE(369);
      END_STATE();
    case 519:
      if (lookahead == 'm') ADVANCE(372);
      END_STATE();
    case 520:
      if (lookahead == 'm') ADVANCE(163);
      END_STATE();
    case 521:
      if (lookahead == 'n') ADVANCE(215);
      END_STATE();
    case 522:
      if (lookahead == 'n') ADVANCE(215);
      if (lookahead == 'q') ADVANCE(961);
      END_STATE();
    case 523:
      if (lookahead == 'n') ADVANCE(196);
      END_STATE();
    case 524:
      if (lookahead == 'n') ADVANCE(989);
      END_STATE();
    case 525:
      if (lookahead == 'n') ADVANCE(1034);
      END_STATE();
    case 526:
      if (lookahead == 'n') ADVANCE(1009);
      END_STATE();
    case 527:
      if (lookahead == 'n') ADVANCE(1033);
      END_STATE();
    case 528:
      if (lookahead == 'n') ADVANCE(1060);
      END_STATE();
    case 529:
      if (lookahead == 'n') ADVANCE(1120);
      END_STATE();
    case 530:
      if (lookahead == 'n') ADVANCE(1121);
      END_STATE();
    case 531:
      if (lookahead == 'n') ADVANCE(1124);
      END_STATE();
    case 532:
      if (lookahead == 'n') ADVANCE(1076);
      END_STATE();
    case 533:
      if (lookahead == 'n') ADVANCE(1057);
      END_STATE();
    case 534:
      if (lookahead == 'n') ADVANCE(1110);
      END_STATE();
    case 535:
      if (lookahead == 'n') ADVANCE(937);
      END_STATE();
    case 536:
      if (lookahead == 'n') ADVANCE(395);
      END_STATE();
    case 537:
      if (lookahead == 'n') ADVANCE(593);
      END_STATE();
    case 538:
      if (lookahead == 'n') ADVANCE(231);
      END_STATE();
    case 539:
      if (lookahead == 'n') ADVANCE(888);
      END_STATE();
    case 540:
      if (lookahead == 'n') ADVANCE(397);
      END_STATE();
    case 541:
      if (lookahead == 'n') ADVANCE(115);
      END_STATE();
    case 542:
      if (lookahead == 'n') ADVANCE(400);
      END_STATE();
    case 543:
      if (lookahead == 'n') ADVANCE(140);
      END_STATE();
    case 544:
      if (lookahead == 'n') ADVANCE(752);
      END_STATE();
    case 545:
      if (lookahead == 'n') ADVANCE(78);
      END_STATE();
    case 546:
      if (lookahead == 'n') ADVANCE(200);
      END_STATE();
    case 547:
      if (lookahead == 'n') ADVANCE(844);
      END_STATE();
    case 548:
      if (lookahead == 'n') ADVANCE(323);
      END_STATE();
    case 549:
      if (lookahead == 'n') ADVANCE(80);
      END_STATE();
    case 550:
      if (lookahead == 'n') ADVANCE(37);
      END_STATE();
    case 551:
      if (lookahead == 'n') ADVANCE(65);
      END_STATE();
    case 552:
      if (lookahead == 'n') ADVANCE(85);
      END_STATE();
    case 553:
      if (lookahead == 'n') ADVANCE(79);
      END_STATE();
    case 554:
      if (lookahead == 'n') ADVANCE(855);
      END_STATE();
    case 555:
      if (lookahead == 'n') ADVANCE(873);
      if (lookahead == 'u') ADVANCE(569);
      END_STATE();
    case 556:
      if (lookahead == 'n') ADVANCE(826);
      END_STATE();
    case 557:
      if (lookahead == 'n') ADVANCE(856);
      END_STATE();
    case 558:
      if (lookahead == 'n') ADVANCE(828);
      END_STATE();
    case 559:
      if (lookahead == 'n') ADVANCE(863);
      END_STATE();
    case 560:
      if (lookahead == 'n') ADVANCE(283);
      END_STATE();
    case 561:
      if (lookahead == 'n') ADVANCE(789);
      END_STATE();
    case 562:
      if (lookahead == 'n') ADVANCE(141);
      if (lookahead == 'r') ADVANCE(291);
      END_STATE();
    case 563:
      if (lookahead == 'n') ADVANCE(150);
      if (lookahead == 't') ADVANCE(748);
      if (lookahead == 'v') ADVANCE(128);
      END_STATE();
    case 564:
      if (lookahead == 'n') ADVANCE(150);
      if (lookahead == 'v') ADVANCE(128);
      END_STATE();
    case 565:
      if (lookahead == 'n') ADVANCE(858);
      END_STATE();
    case 566:
      if (lookahead == 'n') ADVANCE(793);
      END_STATE();
    case 567:
      if (lookahead == 'n') ADVANCE(859);
      END_STATE();
    case 568:
      if (lookahead == 'n') ADVANCE(367);
      END_STATE();
    case 569:
      if (lookahead == 'n') ADVANCE(864);
      END_STATE();
    case 570:
      if (lookahead == 'n') ADVANCE(799);
      END_STATE();
    case 571:
      if (lookahead == 'n') ADVANCE(202);
      END_STATE();
    case 572:
      if (lookahead == 'n') ADVANCE(151);
      if (lookahead == 'v') ADVANCE(156);
      END_STATE();
    case 573:
      if (lookahead == 'n') ADVANCE(195);
      END_STATE();
    case 574:
      if (lookahead == 'n') ADVANCE(152);
      if (lookahead == 'v') ADVANCE(159);
      END_STATE();
    case 575:
      if (lookahead == 'n') ADVANCE(153);
      if (lookahead == 'v') ADVANCE(160);
      END_STATE();
    case 576:
      if (lookahead == 'n') ADVANCE(460);
      END_STATE();
    case 577:
      if (lookahead == 'n') ADVANCE(154);
      if (lookahead == 'v') ADVANCE(161);
      END_STATE();
    case 578:
      if (lookahead == 'n') ADVANCE(162);
      END_STATE();
    case 579:
      if (lookahead == 'n') ADVANCE(100);
      END_STATE();
    case 580:
      if (lookahead == 'o') ADVANCE(468);
      if (lookahead == 'w') ADVANCE(292);
      END_STATE();
    case 581:
      if (lookahead == 'o') ADVANCE(915);
      END_STATE();
    case 582:
      if (lookahead == 'o') ADVANCE(555);
      END_STATE();
    case 583:
      if (lookahead == 'o') ADVANCE(684);
      END_STATE();
    case 584:
      if (lookahead == 'o') ADVANCE(929);
      END_STATE();
    case 585:
      if (lookahead == 'o') ADVANCE(514);
      END_STATE();
    case 586:
      if (lookahead == 'o') ADVANCE(892);
      END_STATE();
    case 587:
      if (lookahead == 'o') ADVANCE(470);
      END_STATE();
    case 588:
      if (lookahead == 'o') ADVANCE(816);
      END_STATE();
    case 589:
      if (lookahead == 'o') ADVANCE(482);
      END_STATE();
    case 590:
      if (lookahead == 'o') ADVANCE(436);
      END_STATE();
    case 591:
      if (lookahead == 'o') ADVANCE(469);
      END_STATE();
    case 592:
      if (lookahead == 'o') ADVANCE(8);
      END_STATE();
    case 593:
      if (lookahead == 'o') ADVANCE(535);
      END_STATE();
    case 594:
      if (lookahead == 'o') ADVANCE(837);
      END_STATE();
    case 595:
      if (lookahead == 'o') ADVANCE(691);
      END_STATE();
    case 596:
      if (lookahead == 'o') ADVANCE(230);
      END_STATE();
    case 597:
      if (lookahead == 'o') ADVANCE(587);
      END_STATE();
    case 598:
      if (lookahead == 'o') ADVANCE(842);
      END_STATE();
    case 599:
      if (lookahead == 'o') ADVANCE(561);
      END_STATE();
    case 600:
      if (lookahead == 'o') ADVANCE(218);
      END_STATE();
    case 601:
      if (lookahead == 'o') ADVANCE(94);
      END_STATE();
    case 602:
      if (lookahead == 'o') ADVANCE(746);
      END_STATE();
    case 603:
      if (lookahead == 'o') ADVANCE(579);
      END_STATE();
    case 604:
      if (lookahead == 'o') ADVANCE(532);
      END_STATE();
    case 605:
      if (lookahead == 'o') ADVANCE(533);
      END_STATE();
    case 606:
      if (lookahead == 'o') ADVANCE(534);
      END_STATE();
    case 607:
      if (lookahead == 'o') ADVANCE(825);
      END_STATE();
    case 608:
      if (lookahead == 'o') ADVANCE(550);
      END_STATE();
    case 609:
      if (lookahead == 'o') ADVANCE(718);
      END_STATE();
    case 610:
      if (lookahead == 'o') ADVANCE(690);
      END_STATE();
    case 611:
      if (lookahead == 'o') ADVANCE(699);
      END_STATE();
    case 612:
      if (lookahead == 'o') ADVANCE(830);
      END_STATE();
    case 613:
      if (lookahead == 'o') ADVANCE(723);
      END_STATE();
    case 614:
      if (lookahead == 'o') ADVANCE(232);
      END_STATE();
    case 615:
      if (lookahead == 'o') ADVANCE(443);
      END_STATE();
    case 616:
      if (lookahead == 'o') ADVANCE(724);
      END_STATE();
    case 617:
      if (lookahead == 'o') ADVANCE(783);
      END_STATE();
    case 618:
      if (lookahead == 'o') ADVANCE(234);
      END_STATE();
    case 619:
      if (lookahead == 'o') ADVANCE(560);
      END_STATE();
    case 620:
      if (lookahead == 'o') ADVANCE(551);
      END_STATE();
    case 621:
      if (lookahead == 'o') ADVANCE(725);
      END_STATE();
    case 622:
      if (lookahead == 'o') ADVANCE(786);
      END_STATE();
    case 623:
      if (lookahead == 'o') ADVANCE(666);
      END_STATE();
    case 624:
      if (lookahead == 'o') ADVANCE(726);
      END_STATE();
    case 625:
      if (lookahead == 'o') ADVANCE(788);
      END_STATE();
    case 626:
      if (lookahead == 'o') ADVANCE(238);
      END_STATE();
    case 627:
      if (lookahead == 'o') ADVANCE(729);
      END_STATE();
    case 628:
      if (lookahead == 'o') ADVANCE(553);
      END_STATE();
    case 629:
      if (lookahead == 'o') ADVANCE(732);
      END_STATE();
    case 630:
      if (lookahead == 'o') ADVANCE(239);
      END_STATE();
    case 631:
      if (lookahead == 'o') ADVANCE(731);
      END_STATE();
    case 632:
      if (lookahead == 'o') ADVANCE(240);
      END_STATE();
    case 633:
      if (lookahead == 'o') ADVANCE(735);
      END_STATE();
    case 634:
      if (lookahead == 'o') ADVANCE(241);
      END_STATE();
    case 635:
      if (lookahead == 'o') ADVANCE(242);
      END_STATE();
    case 636:
      if (lookahead == 'o') ADVANCE(243);
      END_STATE();
    case 637:
      if (lookahead == 'o') ADVANCE(472);
      END_STATE();
    case 638:
      if (lookahead == 'o') ADVANCE(246);
      END_STATE();
    case 639:
      if (lookahead == 'o') ADVANCE(637);
      END_STATE();
    case 640:
      if (lookahead == 'o') ADVANCE(566);
      END_STATE();
    case 641:
      if (lookahead == 'o') ADVANCE(570);
      END_STATE();
    case 642:
      if (lookahead == 'o') ADVANCE(98);
      END_STATE();
    case 643:
      if (lookahead == 'o') ADVANCE(99);
      END_STATE();
    case 644:
      if (lookahead == 'o') ADVANCE(885);
      END_STATE();
    case 645:
      if (lookahead == 'p') ADVANCE(1117);
      END_STATE();
    case 646:
      if (lookahead == 'p') ADVANCE(1084);
      END_STATE();
    case 647:
      if (lookahead == 'p') ADVANCE(1086);
      END_STATE();
    case 648:
      if (lookahead == 'p') ADVANCE(1078);
      END_STATE();
    case 649:
      if (lookahead == 'p') ADVANCE(1046);
      END_STATE();
    case 650:
      if (lookahead == 'p') ADVANCE(1083);
      END_STATE();
    case 651:
      if (lookahead == 'p') ADVANCE(1085);
      END_STATE();
    case 652:
      if (lookahead == 'p') ADVANCE(1077);
      END_STATE();
    case 653:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 654:
      if (lookahead == 'p') ADVANCE(526);
      END_STATE();
    case 655:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 656:
      if (lookahead == 'p') ADVANCE(47);
      END_STATE();
    case 657:
      if (lookahead == 'p') ADVANCE(62);
      END_STATE();
    case 658:
      if (lookahead == 'p') ADVANCE(298);
      END_STATE();
    case 659:
      if (lookahead == 'p') ADVANCE(835);
      END_STATE();
    case 660:
      if (lookahead == 'p') ADVANCE(483);
      END_STATE();
    case 661:
      if (lookahead == 'p') ADVANCE(708);
      END_STATE();
    case 662:
      if (lookahead == 'p') ADVANCE(266);
      END_STATE();
    case 663:
      if (lookahead == 'p') ADVANCE(15);
      END_STATE();
    case 664:
      if (lookahead == 'p') ADVANCE(22);
      END_STATE();
    case 665:
      if (lookahead == 'p') ADVANCE(269);
      END_STATE();
    case 666:
      if (lookahead == 'p') ADVANCE(356);
      END_STATE();
    case 667:
      if (lookahead == 'p') ADVANCE(279);
      END_STATE();
    case 668:
      if (lookahead == 'p') ADVANCE(295);
      END_STATE();
    case 669:
      if (lookahead == 'p') ADVANCE(599);
      END_STATE();
    case 670:
      if (lookahead == 'p') ADVANCE(135);
      END_STATE();
    case 671:
      if (lookahead == 'p') ADVANCE(866);
      END_STATE();
    case 672:
      if (lookahead == 'p') ADVANCE(613);
      END_STATE();
    case 673:
      if (lookahead == 'p') ADVANCE(616);
      END_STATE();
    case 674:
      if (lookahead == 'p') ADVANCE(621);
      END_STATE();
    case 675:
      if (lookahead == 'p') ADVANCE(624);
      END_STATE();
    case 676:
      if (lookahead == 'p') ADVANCE(804);
      END_STATE();
    case 677:
      if (lookahead == 'p') ADVANCE(640);
      END_STATE();
    case 678:
      if (lookahead == 'p') ADVANCE(641);
      END_STATE();
    case 679:
      if (lookahead == 'p') ADVANCE(50);
      END_STATE();
    case 680:
      if (lookahead == 'q') ADVANCE(961);
      END_STATE();
    case 681:
      if (lookahead == 'q') ADVANCE(484);
      END_STATE();
    case 682:
      if (lookahead == 'q') ADVANCE(909);
      END_STATE();
    case 683:
      if (lookahead == 'r') ADVANCE(956);
      END_STATE();
    case 684:
      if (lookahead == 'r') ADVANCE(954);
      END_STATE();
    case 685:
      if (lookahead == 'r') ADVANCE(982);
      END_STATE();
    case 686:
      if (lookahead == 'r') ADVANCE(986);
      END_STATE();
    case 687:
      if (lookahead == 'r') ADVANCE(1009);
      END_STATE();
    case 688:
      if (lookahead == 'r') ADVANCE(1050);
      END_STATE();
    case 689:
      if (lookahead == 'r') ADVANCE(1119);
      END_STATE();
    case 690:
      if (lookahead == 'r') ADVANCE(1058);
      END_STATE();
    case 691:
      if (lookahead == 'r') ADVANCE(471);
      END_STATE();
    case 692:
      if (lookahead == 'r') ADVANCE(174);
      END_STATE();
    case 693:
      if (lookahead == 'r') ADVANCE(206);
      END_STATE();
    case 694:
      if (lookahead == 'r') ADVANCE(918);
      END_STATE();
    case 695:
      if (lookahead == 'r') ADVANCE(396);
      END_STATE();
    case 696:
      if (lookahead == 'r') ADVANCE(881);
      END_STATE();
    case 697:
      if (lookahead == 'r') ADVANCE(932);
      END_STATE();
    case 698:
      if (lookahead == 'r') ADVANCE(933);
      END_STATE();
    case 699:
      if (lookahead == 'r') ADVANCE(499);
      END_STATE();
    case 700:
      if (lookahead == 'r') ADVANCE(74);
      END_STATE();
    case 701:
      if (lookahead == 'r') ADVANCE(934);
      END_STATE();
    case 702:
      if (lookahead == 'r') ADVANCE(44);
      END_STATE();
    case 703:
      if (lookahead == 'r') ADVANCE(424);
      END_STATE();
    case 704:
      if (lookahead == 'r') ADVANCE(935);
      END_STATE();
    case 705:
      if (lookahead == 'r') ADVANCE(936);
      END_STATE();
    case 706:
      if (lookahead == 'r') ADVANCE(92);
      END_STATE();
    case 707:
      if (lookahead == 'r') ADVANCE(361);
      END_STATE();
    case 708:
      if (lookahead == 'r') ADVANCE(584);
      END_STATE();
    case 709:
      if (lookahead == 'r') ADVANCE(426);
      END_STATE();
    case 710:
      if (lookahead == 'r') ADVANCE(601);
      END_STATE();
    case 711:
      if (lookahead == 'r') ADVANCE(427);
      END_STATE();
    case 712:
      if (lookahead == 'r') ADVANCE(315);
      END_STATE();
    case 713:
      if (lookahead == 'r') ADVANCE(64);
      END_STATE();
    case 714:
      if (lookahead == 'r') ADVANCE(430);
      END_STATE();
    case 715:
      if (lookahead == 'r') ADVANCE(428);
      END_STATE();
    case 716:
      if (lookahead == 'r') ADVANCE(190);
      END_STATE();
    case 717:
      if (lookahead == 'r') ADVANCE(623);
      END_STATE();
    case 718:
      if (lookahead == 'r') ADVANCE(95);
      END_STATE();
    case 719:
      if (lookahead == 'r') ADVANCE(809);
      END_STATE();
    case 720:
      if (lookahead == 'r') ADVANCE(757);
      END_STATE();
    case 721:
      if (lookahead == 'r') ADVANCE(759);
      END_STATE();
    case 722:
      if (lookahead == 'r') ADVANCE(263);
      END_STATE();
    case 723:
      if (lookahead == 'r') ADVANCE(821);
      END_STATE();
    case 724:
      if (lookahead == 'r') ADVANCE(822);
      END_STATE();
    case 725:
      if (lookahead == 'r') ADVANCE(823);
      END_STATE();
    case 726:
      if (lookahead == 'r') ADVANCE(824);
      END_STATE();
    case 727:
      if (lookahead == 'r') ADVANCE(745);
      END_STATE();
    case 728:
      if (lookahead == 'r') ADVANCE(270);
      END_STATE();
    case 729:
      if (lookahead == 'r') ADVANCE(272);
      END_STATE();
    case 730:
      if (lookahead == 'r') ADVANCE(773);
      END_STATE();
    case 731:
      if (lookahead == 'r') ADVANCE(274);
      END_STATE();
    case 732:
      if (lookahead == 'r') ADVANCE(829);
      END_STATE();
    case 733:
      if (lookahead == 'r') ADVANCE(304);
      END_STATE();
    case 734:
      if (lookahead == 'r') ADVANCE(861);
      END_STATE();
    case 735:
      if (lookahead == 'r') ADVANCE(282);
      END_STATE();
    case 736:
      if (lookahead == 'r') ADVANCE(294);
      if (lookahead == 'v') ADVANCE(375);
      END_STATE();
    case 737:
      if (lookahead == 'r') ADVANCE(403);
      END_STATE();
    case 738:
      if (lookahead == 'r') ADVANCE(895);
      END_STATE();
    case 739:
      if (lookahead == 'r') ADVANCE(435);
      END_STATE();
    case 740:
      if (lookahead == 'r') ADVANCE(192);
      if (lookahead == 's') ADVANCE(681);
      if (lookahead == 'x') ADVANCE(785);
      END_STATE();
    case 741:
      if (lookahead == 'r') ADVANCE(404);
      END_STATE();
    case 742:
      if (lookahead == 'r') ADVANCE(237);
      END_STATE();
    case 743:
      if (lookahead == 'r') ADVANCE(442);
      END_STATE();
    case 744:
      if (lookahead == 'r') ADVANCE(324);
      END_STATE();
    case 745:
      if (lookahead == 'r') ADVANCE(609);
      END_STATE();
    case 746:
      if (lookahead == 'r') ADVANCE(925);
      END_STATE();
    case 747:
      if (lookahead == 'r') ADVANCE(462);
      END_STATE();
    case 748:
      if (lookahead == 'r') ADVANCE(910);
      END_STATE();
    case 749:
      if (lookahead == 'r') ADVANCE(208);
      END_STATE();
    case 750:
      if (lookahead == 's') ADVANCE(1009);
      END_STATE();
    case 751:
      if (lookahead == 's') ADVANCE(975);
      END_STATE();
    case 752:
      if (lookahead == 's') ADVANCE(974);
      END_STATE();
    case 753:
      if (lookahead == 's') ADVANCE(1037);
      END_STATE();
    case 754:
      if (lookahead == 's') ADVANCE(984);
      END_STATE();
    case 755:
      if (lookahead == 's') ADVANCE(1029);
      END_STATE();
    case 756:
      if (lookahead == 's') ADVANCE(1091);
      END_STATE();
    case 757:
      if (lookahead == 's') ADVANCE(1094);
      END_STATE();
    case 758:
      if (lookahead == 's') ADVANCE(1092);
      END_STATE();
    case 759:
      if (lookahead == 's') ADVANCE(1097);
      END_STATE();
    case 760:
      if (lookahead == 's') ADVANCE(1093);
      END_STATE();
    case 761:
      if (lookahead == 's') ADVANCE(1102);
      END_STATE();
    case 762:
      if (lookahead == 's') ADVANCE(1103);
      END_STATE();
    case 763:
      if (lookahead == 's') ADVANCE(1098);
      END_STATE();
    case 764:
      if (lookahead == 's') ADVANCE(1107);
      END_STATE();
    case 765:
      if (lookahead == 's') ADVANCE(1105);
      END_STATE();
    case 766:
      if (lookahead == 's') ADVANCE(1099);
      END_STATE();
    case 767:
      if (lookahead == 's') ADVANCE(1108);
      END_STATE();
    case 768:
      if (lookahead == 's') ADVANCE(1106);
      END_STATE();
    case 769:
      if (lookahead == 's') ADVANCE(1109);
      END_STATE();
    case 770:
      if (lookahead == 's') ADVANCE(1104);
      END_STATE();
    case 771:
      if (lookahead == 's') ADVANCE(1100);
      END_STATE();
    case 772:
      if (lookahead == 's') ADVANCE(1101);
      END_STATE();
    case 773:
      if (lookahead == 's') ADVANCE(1095);
      END_STATE();
    case 774:
      if (lookahead == 's') ADVANCE(68);
      END_STATE();
    case 775:
      if (lookahead == 's') ADVANCE(262);
      END_STATE();
    case 776:
      if (lookahead == 's') ADVANCE(411);
      END_STATE();
    case 777:
      if (lookahead == 's') ADVANCE(73);
      END_STATE();
    case 778:
      if (lookahead == 's') ADVANCE(199);
      END_STATE();
    case 779:
      if (lookahead == 's') ADVANCE(847);
      END_STATE();
    case 780:
      if (lookahead == 's') ADVANCE(818);
      END_STATE();
    case 781:
      if (lookahead == 's') ADVANCE(669);
      END_STATE();
    case 782:
      if (lookahead == 's') ADVANCE(414);
      END_STATE();
    case 783:
      if (lookahead == 's') ADVANCE(848);
      END_STATE();
    case 784:
      if (lookahead == 's') ADVANCE(87);
      END_STATE();
    case 785:
      if (lookahead == 's') ADVANCE(755);
      END_STATE();
    case 786:
      if (lookahead == 's') ADVANCE(819);
      END_STATE();
    case 787:
      if (lookahead == 's') ADVANCE(539);
      END_STATE();
    case 788:
      if (lookahead == 's') ADVANCE(871);
      END_STATE();
    case 789:
      if (lookahead == 's') ADVANCE(306);
      END_STATE();
    case 790:
      if (lookahead == 's') ADVANCE(850);
      END_STATE();
    case 791:
      if (lookahead == 's') ADVANCE(348);
      END_STATE();
    case 792:
      if (lookahead == 's') ADVANCE(854);
      END_STATE();
    case 793:
      if (lookahead == 's') ADVANCE(311);
      END_STATE();
    case 794:
      if (lookahead == 's') ADVANCE(853);
      END_STATE();
    case 795:
      if (lookahead == 's') ADVANCE(860);
      END_STATE();
    case 796:
      if (lookahead == 's') ADVANCE(862);
      END_STATE();
    case 797:
      if (lookahead == 's') ADVANCE(319);
      END_STATE();
    case 798:
      if (lookahead == 's') ADVANCE(327);
      END_STATE();
    case 799:
      if (lookahead == 's') ADVANCE(333);
      END_STATE();
    case 800:
      if (lookahead == 's') ADVANCE(852);
      END_STATE();
    case 801:
      if (lookahead == 's') ADVANCE(603);
      END_STATE();
    case 802:
      if (lookahead == 's') ADVANCE(344);
      END_STATE();
    case 803:
      if (lookahead == 's') ADVANCE(307);
      END_STATE();
    case 804:
      if (lookahead == 's') ADVANCE(874);
      END_STATE();
    case 805:
      if (lookahead == 's') ADVANCE(320);
      END_STATE();
    case 806:
      if (lookahead == 's') ADVANCE(798);
      END_STATE();
    case 807:
      if (lookahead == 's') ADVANCE(89);
      END_STATE();
    case 808:
      if (lookahead == 's') ADVANCE(201);
      END_STATE();
    case 809:
      if (lookahead == 's') ADVANCE(456);
      END_STATE();
    case 810:
      if (lookahead == 's') ADVANCE(878);
      END_STATE();
    case 811:
      if (lookahead == 's') ADVANCE(458);
      END_STATE();
    case 812:
      if (lookahead == 's') ADVANCE(876);
      END_STATE();
    case 813:
      if (lookahead == 's') ADVANCE(642);
      END_STATE();
    case 814:
      if (lookahead == 's') ADVANCE(643);
      END_STATE();
    case 815:
      if (lookahead == 't') ADVANCE(173);
      END_STATE();
    case 816:
      if (lookahead == 't') ADVANCE(1014);
      END_STATE();
    case 817:
      if (lookahead == 't') ADVANCE(977);
      END_STATE();
    case 818:
      if (lookahead == 't') ADVANCE(1047);
      END_STATE();
    case 819:
      if (lookahead == 't') ADVANCE(1049);
      END_STATE();
    case 820:
      if (lookahead == 't') ADVANCE(1059);
      END_STATE();
    case 821:
      if (lookahead == 't') ADVANCE(1039);
      END_STATE();
    case 822:
      if (lookahead == 't') ADVANCE(1038);
      END_STATE();
    case 823:
      if (lookahead == 't') ADVANCE(1040);
      END_STATE();
    case 824:
      if (lookahead == 't') ADVANCE(1041);
      END_STATE();
    case 825:
      if (lookahead == 't') ADVANCE(1114);
      END_STATE();
    case 826:
      if (lookahead == 't') ADVANCE(1056);
      END_STATE();
    case 827:
      if (lookahead == 't') ADVANCE(1123);
      END_STATE();
    case 828:
      if (lookahead == 't') ADVANCE(1064);
      END_STATE();
    case 829:
      if (lookahead == 't') ADVANCE(1025);
      END_STATE();
    case 830:
      if (lookahead == 't') ADVANCE(1112);
      END_STATE();
    case 831:
      if (lookahead == 't') ADVANCE(836);
      END_STATE();
    case 832:
      if (lookahead == 't') ADVANCE(409);
      END_STATE();
    case 833:
      if (lookahead == 't') ADVANCE(410);
      END_STATE();
    case 834:
      if (lookahead == 't') ADVANCE(931);
      END_STATE();
    case 835:
      if (lookahead == 't') ADVANCE(36);
      END_STATE();
    case 836:
      if (lookahead == 't') ADVANCE(653);
      END_STATE();
    case 837:
      if (lookahead == 't') ADVANCE(67);
      END_STATE();
    case 838:
      if (lookahead == 't') ADVANCE(476);
      END_STATE();
    case 839:
      if (lookahead == 't') ADVANCE(418);
      END_STATE();
    case 840:
      if (lookahead == 't') ADVANCE(183);
      END_STATE();
    case 841:
      if (lookahead == 't') ADVANCE(419);
      END_STATE();
    case 842:
      if (lookahead == 't') ADVANCE(548);
      END_STATE();
    case 843:
      if (lookahead == 't') ADVANCE(412);
      END_STATE();
    case 844:
      if (lookahead == 't') ADVANCE(28);
      END_STATE();
    case 845:
      if (lookahead == 't') ADVANCE(413);
      END_STATE();
    case 846:
      if (lookahead == 't') ADVANCE(123);
      END_STATE();
    case 847:
      if (lookahead == 't') ADVANCE(739);
      END_STATE();
    case 848:
      if (lookahead == 't') ADVANCE(541);
      END_STATE();
    case 849:
      if (lookahead == 't') ADVANCE(107);
      END_STATE();
    case 850:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 851:
      if (lookahead == 't') ADVANCE(656);
      END_STATE();
    case 852:
      if (lookahead == 't') ADVANCE(672);
      END_STATE();
    case 853:
      if (lookahead == 't') ADVANCE(139);
      END_STATE();
    case 854:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 855:
      if (lookahead == 't') ADVANCE(76);
      END_STATE();
    case 856:
      if (lookahead == 't') ADVANCE(13);
      END_STATE();
    case 857:
      if (lookahead == 't') ADVANCE(710);
      END_STATE();
    case 858:
      if (lookahead == 't') ADVANCE(697);
      END_STATE();
    case 859:
      if (lookahead == 't') ADVANCE(698);
      END_STATE();
    case 860:
      if (lookahead == 't') ADVANCE(45);
      END_STATE();
    case 861:
      if (lookahead == 't') ADVANCE(66);
      END_STATE();
    case 862:
      if (lookahead == 't') ADVANCE(23);
      END_STATE();
    case 863:
      if (lookahead == 't') ADVANCE(27);
      END_STATE();
    case 864:
      if (lookahead == 't') ADVANCE(701);
      END_STATE();
    case 865:
      if (lookahead == 't') ADVANCE(308);
      END_STATE();
    case 866:
      if (lookahead == 't') ADVANCE(312);
      END_STATE();
    case 867:
      if (lookahead == 't') ADVANCE(309);
      END_STATE();
    case 868:
      if (lookahead == 't') ADVANCE(317);
      END_STATE();
    case 869:
      if (lookahead == 't') ADVANCE(321);
      END_STATE();
    case 870:
      if (lookahead == 't') ADVANCE(851);
      END_STATE();
    case 871:
      if (lookahead == 't') ADVANCE(124);
      END_STATE();
    case 872:
      if (lookahead == 't') ADVANCE(93);
      END_STATE();
    case 873:
      if (lookahead == 't') ADVANCE(451);
      END_STATE();
    case 874:
      if (lookahead == 't') ADVANCE(733);
      END_STATE();
    case 875:
      if (lookahead == 't') ADVANCE(943);
      END_STATE();
    case 876:
      if (lookahead == 't') ADVANCE(743);
      END_STATE();
    case 877:
      if (lookahead == 't') ADVANCE(944);
      END_STATE();
    case 878:
      if (lookahead == 't') ADVANCE(674);
      END_STATE();
    case 879:
      if (lookahead == 't') ADVANCE(459);
      END_STATE();
    case 880:
      if (lookahead == 't') ADVANCE(461);
      END_STATE();
    case 881:
      if (lookahead == 't') ADVANCE(807);
      END_STATE();
    case 882:
      if (lookahead == 't') ADVANCE(679);
      END_STATE();
    case 883:
      if (lookahead == 't') ADVANCE(380);
      END_STATE();
    case 884:
      if (lookahead == 't') ADVANCE(882);
      END_STATE();
    case 885:
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 886:
      if (lookahead == 'u') ADVANCE(261);
      END_STATE();
    case 887:
      if (lookahead == 'u') ADVANCE(167);
      END_STATE();
    case 888:
      if (lookahead == 'u') ADVANCE(498);
      END_STATE();
    case 889:
      if (lookahead == 'u') ADVANCE(657);
      END_STATE();
    case 890:
      if (lookahead == 'u') ADVANCE(487);
      END_STATE();
    case 891:
      if (lookahead == 'u') ADVANCE(776);
      END_STATE();
    case 892:
      if (lookahead == 'u') ADVANCE(565);
      END_STATE();
    case 893:
      if (lookahead == 'u') ADVANCE(676);
      END_STATE();
    case 894:
      if (lookahead == 'u') ADVANCE(368);
      END_STATE();
    case 895:
      if (lookahead == 'u') ADVANCE(546);
      END_STATE();
    case 896:
      if (lookahead == 'u') ADVANCE(576);
      END_STATE();
    case 897:
      if (lookahead == 'u') ADVANCE(717);
      END_STATE();
    case 898:
      if (lookahead == 'u') ADVANCE(711);
      END_STATE();
    case 899:
      if (lookahead == 'u') ADVANCE(841);
      END_STATE();
    case 900:
      if (lookahead == 'u') ADVANCE(715);
      END_STATE();
    case 901:
      if (lookahead == 'u') ADVANCE(332);
      END_STATE();
    case 902:
      if (lookahead == 'u') ADVANCE(338);
      END_STATE();
    case 903:
      if (lookahead == 'u') ADVANCE(340);
      END_STATE();
    case 904:
      if (lookahead == 'u') ADVANCE(342);
      END_STATE();
    case 905:
      if (lookahead == 'u') ADVANCE(349);
      END_STATE();
    case 906:
      if (lookahead == 'u') ADVANCE(352);
      END_STATE();
    case 907:
      if (lookahead == 'u') ADVANCE(353);
      END_STATE();
    case 908:
      if (lookahead == 'u') ADVANCE(567);
      END_STATE();
    case 909:
      if (lookahead == 'u') ADVANCE(371);
      END_STATE();
    case 910:
      if (lookahead == 'u') ADVANCE(571);
      END_STATE();
    case 911:
      if (lookahead == 'u') ADVANCE(146);
      END_STATE();
    case 912:
      if (lookahead == 'u') ADVANCE(373);
      END_STATE();
    case 913:
      if (lookahead == 'u') ADVANCE(496);
      END_STATE();
    case 914:
      if (lookahead == 'v') ADVANCE(57);
      END_STATE();
    case 915:
      if (lookahead == 'v') ADVANCE(302);
      END_STATE();
    case 916:
      if (lookahead == 'v') ADVANCE(463);
      END_STATE();
    case 917:
      if (lookahead == 'v') ADVANCE(591);
      END_STATE();
    case 918:
      if (lookahead == 'v') ADVANCE(329);
      END_STATE();
    case 919:
      if (lookahead == 'w') ADVANCE(1087);
      END_STATE();
    case 920:
      if (lookahead == 'w') ADVANCE(26);
      END_STATE();
    case 921:
      if (lookahead == 'w') ADVANCE(437);
      END_STATE();
    case 922:
      if (lookahead == 'w') ADVANCE(689);
      END_STATE();
    case 923:
      if (lookahead == 'w') ADVANCE(145);
      END_STATE();
    case 924:
      if (lookahead == 'w') ADVANCE(441);
      END_STATE();
    case 925:
      if (lookahead == 'w') ADVANCE(131);
      END_STATE();
    case 926:
      if (lookahead == 'x') ADVANCE(81);
      END_STATE();
    case 927:
      if (lookahead == 'x') ADVANCE(928);
      END_STATE();
    case 928:
      if (lookahead == 'x') ADVANCE(930);
      END_STATE();
    case 929:
      if (lookahead == 'x') ADVANCE(446);
      END_STATE();
    case 930:
      if (lookahead == 'x') ADVANCE(97);
      END_STATE();
    case 931:
      if (lookahead == 'y') ADVANCE(1061);
      END_STATE();
    case 932:
      if (lookahead == 'y') ADVANCE(1081);
      END_STATE();
    case 933:
      if (lookahead == 'y') ADVANCE(1082);
      END_STATE();
    case 934:
      if (lookahead == 'y') ADVANCE(1065);
      END_STATE();
    case 935:
      if (lookahead == 'y') ADVANCE(1055);
      END_STATE();
    case 936:
      if (lookahead == 'y') ADVANCE(1071);
      END_STATE();
    case 937:
      if (lookahead == 'y') ADVANCE(502);
      END_STATE();
    case 938:
      if (lookahead == 'y') ADVANCE(14);
      END_STATE();
    case 939:
      if (lookahead == 'y') ADVANCE(865);
      END_STATE();
    case 940:
      if (lookahead == 'y') ADVANCE(531);
      END_STATE();
    case 941:
      if (lookahead == 'y') ADVANCE(24);
      END_STATE();
    case 942:
      if (lookahead == 'y') ADVANCE(662);
      END_STATE();
    case 943:
      if (lookahead == 'y') ADVANCE(665);
      END_STATE();
    case 944:
      if (lookahead == 'y') ADVANCE(667);
      END_STATE();
    case 945:
      if (lookahead == 'z') ADVANCE(281);
      END_STATE();
    case 946:
      if (lookahead == 'z') ADVANCE(619);
      END_STATE();
    case 947:
      if (lookahead == 'z') ADVANCE(328);
      END_STATE();
    case 948:
      if (lookahead == '|') ADVANCE(957);
      END_STATE();
    case 949:
      if (eof) ADVANCE(950);
      if (lookahead == '!') ADVANCE(1015);
      if (lookahead == '#') ADVANCE(960);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(978);
      if (lookahead == ')') ADVANCE(980);
      if (lookahead == '/') ADVANCE(1005);
      if (lookahead == '2') ADVANCE(17);
      if (lookahead == '[') ADVANCE(1017);
      if (lookahead == '^') ADVANCE(61);
      if (lookahead == 'a') ADVANCE(473);
      if (lookahead == 'c') ADVANCE(386);
      if (lookahead == 'e') ADVANCE(521);
      if (lookahead == 'f') ADVANCE(108);
      if (lookahead == 'h') ADVANCE(831);
      if (lookahead == 'i') ADVANCE(172);
      if (lookahead == 'l') ADVANCE(339);
      if (lookahead == 'n') ADVANCE(588);
      if (lookahead == 'o') ADVANCE(683);
      if (lookahead == 'r') ADVANCE(103);
      if (lookahead == 's') ADVANCE(422);
      if (lookahead == 't') ADVANCE(179);
      if (lookahead == 'u') ADVANCE(225);
      if (lookahead == 'x') ADVANCE(583);
      if (lookahead == '|') ADVANCE(948);
      if (lookahead == '}') ADVANCE(959);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(19);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(949)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(20);
      END_STATE();
    case 950:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 951:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 952:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 953:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 954:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 955:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 956:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 957:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 958:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 959:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 960:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(960);
      END_STATE();
    case 961:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 962:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 963:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 964:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 965:
      ACCEPT_TOKEN(anon_sym_le);
      if (lookahead == 'n') ADVANCE(989);
      END_STATE();
    case 966:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 967:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 968:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 969:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 970:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(971);
      END_STATE();
    case 971:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 972:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(973);
      END_STATE();
    case 973:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 974:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 975:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 976:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 977:
      ACCEPT_TOKEN(anon_sym_concat);
      END_STATE();
    case 978:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 979:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 980:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 981:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 982:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 983:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 984:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 985:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 986:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 987:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 988:
      ACCEPT_TOKEN(anon_sym_uuidv4);
      END_STATE();
    case 989:
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 990:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 991:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 992:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 993:
      ACCEPT_TOKEN(anon_sym_all);
      END_STATE();
    case 994:
      ACCEPT_TOKEN(anon_sym_LBRACK_STAR_RBRACK);
      END_STATE();
    case 995:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(996);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(996);
      END_STATE();
    case 996:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(996);
      END_STATE();
    case 997:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 998:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 999:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 1000:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 1001:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(1002);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(1000);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(1003);
      END_STATE();
    case 1002:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(1000);
      END_STATE();
    case 1003:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1000);
      END_STATE();
    case 1004:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1003);
      END_STATE();
    case 1005:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 1006:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 1007:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1006);
      END_STATE();
    case 1008:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1006);
      END_STATE();
    case 1009:
      ACCEPT_TOKEN(sym_ip_list);
      END_STATE();
    case 1010:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == '.') ADVANCE(109);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1013);
      END_STATE();
    case 1011:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'c') ADVANCE(1012);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1013);
      END_STATE();
    case 1012:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'f') ADVANCE(1010);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1013);
      END_STATE();
    case 1013:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1013);
      END_STATE();
    case 1014:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 1015:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 1016:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(969);
      END_STATE();
    case 1017:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 1018:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      if (lookahead == '*') ADVANCE(60);
      END_STATE();
    case 1019:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 1020:
      ACCEPT_TOKEN(anon_sym_STAR);
      END_STATE();
    case 1021:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 1022:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 1023:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 1024:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 1025:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 1026:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 1027:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(740);
      END_STATE();
    case 1028:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 1029:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 1030:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 1031:
      ACCEPT_TOKEN(anon_sym_icmp_DOTtype);
      END_STATE();
    case 1032:
      ACCEPT_TOKEN(anon_sym_icmp_DOTcode);
      END_STATE();
    case 1033:
      ACCEPT_TOKEN(anon_sym_ip_DOThdr_len);
      END_STATE();
    case 1034:
      ACCEPT_TOKEN(anon_sym_ip_DOTlen);
      END_STATE();
    case 1035:
      ACCEPT_TOKEN(anon_sym_ip_DOTopt_DOTtype);
      END_STATE();
    case 1036:
      ACCEPT_TOKEN(anon_sym_ip_DOTttl);
      END_STATE();
    case 1037:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags);
      if (lookahead == '.') ADVANCE(122);
      END_STATE();
    case 1038:
      ACCEPT_TOKEN(anon_sym_tcp_DOTsrcport);
      END_STATE();
    case 1039:
      ACCEPT_TOKEN(anon_sym_tcp_DOTdstport);
      END_STATE();
    case 1040:
      ACCEPT_TOKEN(anon_sym_udp_DOTdstport);
      END_STATE();
    case 1041:
      ACCEPT_TOKEN(anon_sym_udp_DOTsrcport);
      END_STATE();
    case 1042:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTsize);
      END_STATE();
    case 1043:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTcode);
      END_STATE();
    case 1044:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOT1xxx_code);
      END_STATE();
    case 1045:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(176);
      END_STATE();
    case 1046:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 1047:
      ACCEPT_TOKEN(anon_sym_ip_DOTdst);
      if (lookahead == '.') ADVANCE(186);
      END_STATE();
    case 1048:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 1049:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 1050:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 1051:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 1052:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 1053:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(134);
      END_STATE();
    case 1054:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 1055:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 1056:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 1057:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 1058:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 1059:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 1060:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 1061:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 1062:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 1063:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 1064:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 1065:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 1066:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 1067:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 1068:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 1069:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(157);
      END_STATE();
    case 1070:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 1071:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 1072:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 1073:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 1074:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 1075:
      ACCEPT_TOKEN(anon_sym_cf_DOTcolo_DOTname);
      END_STATE();
    case 1076:
      ACCEPT_TOKEN(anon_sym_cf_DOTcolo_DOTregion);
      END_STATE();
    case 1077:
      ACCEPT_TOKEN(anon_sym_icmp);
      END_STATE();
    case 1078:
      ACCEPT_TOKEN(anon_sym_icmp);
      if (lookahead == '.') ADVANCE(184);
      END_STATE();
    case 1079:
      ACCEPT_TOKEN(anon_sym_ip);
      if (lookahead == '.') ADVANCE(244);
      END_STATE();
    case 1080:
      ACCEPT_TOKEN(anon_sym_ip);
      if (lookahead == '.') ADVANCE(249);
      END_STATE();
    case 1081:
      ACCEPT_TOKEN(anon_sym_ip_DOTdst_DOTcountry);
      END_STATE();
    case 1082:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcountry);
      END_STATE();
    case 1083:
      ACCEPT_TOKEN(anon_sym_tcp);
      END_STATE();
    case 1084:
      ACCEPT_TOKEN(anon_sym_tcp);
      if (lookahead == '.') ADVANCE(226);
      END_STATE();
    case 1085:
      ACCEPT_TOKEN(anon_sym_udp);
      END_STATE();
    case 1086:
      ACCEPT_TOKEN(anon_sym_udp);
      if (lookahead == '.') ADVANCE(254);
      END_STATE();
    case 1087:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTraw);
      END_STATE();
    case 1088:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTmime);
      END_STATE();
    case 1089:
      ACCEPT_TOKEN(anon_sym_cf_DOTresponse_DOTerror_type);
      END_STATE();
    case 1090:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 1091:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 1092:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs);
      if (lookahead == '.') ADVANCE(572);
      END_STATE();
    case 1093:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs);
      if (lookahead == '.') ADVANCE(577);
      END_STATE();
    case 1094:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(563);
      END_STATE();
    case 1095:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(564);
      END_STATE();
    case 1096:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform);
      if (lookahead == '.') ADVANCE(575);
      END_STATE();
    case 1097:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders);
      if (lookahead == '.') ADVANCE(574);
      END_STATE();
    case 1098:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames);
      END_STATE();
    case 1099:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues);
      END_STATE();
    case 1100:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames);
      END_STATE();
    case 1101:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues);
      END_STATE();
    case 1102:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTnames);
      END_STATE();
    case 1103:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTvalues);
      END_STATE();
    case 1104:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTaccepted_languages);
      END_STATE();
    case 1105:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames);
      END_STATE();
    case 1106:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues);
      END_STATE();
    case 1107:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders_DOTnames);
      END_STATE();
    case 1108:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders_DOTvalues);
      END_STATE();
    case 1109:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTdetection_ids);
      END_STATE();
    case 1110:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 1111:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 1112:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 1113:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 1114:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 1115:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 1116:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    case 1117:
      ACCEPT_TOKEN(anon_sym_sip);
      END_STATE();
    case 1118:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTack);
      END_STATE();
    case 1119:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTcwr);
      END_STATE();
    case 1120:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTecn);
      END_STATE();
    case 1121:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTfin);
      END_STATE();
    case 1122:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTpush);
      END_STATE();
    case 1123:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTreset);
      END_STATE();
    case 1124:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTsyn);
      END_STATE();
    case 1125:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTurg);
      END_STATE();
    case 1126:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTtruncated);
      END_STATE();
    case 1127:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTtruncated);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 949},
  [2] = {.lex_state = 949},
  [3] = {.lex_state = 949},
  [4] = {.lex_state = 949},
  [5] = {.lex_state = 949},
  [6] = {.lex_state = 949},
  [7] = {.lex_state = 949},
  [8] = {.lex_state = 949},
  [9] = {.lex_state = 949},
  [10] = {.lex_state = 949},
  [11] = {.lex_state = 949},
  [12] = {.lex_state = 949},
  [13] = {.lex_state = 949},
  [14] = {.lex_state = 949},
  [15] = {.lex_state = 949},
  [16] = {.lex_state = 949},
  [17] = {.lex_state = 949},
  [18] = {.lex_state = 949},
  [19] = {.lex_state = 949},
  [20] = {.lex_state = 949},
  [21] = {.lex_state = 949},
  [22] = {.lex_state = 949},
  [23] = {.lex_state = 949},
  [24] = {.lex_state = 949},
  [25] = {.lex_state = 949},
  [26] = {.lex_state = 949},
  [27] = {.lex_state = 949},
  [28] = {.lex_state = 949},
  [29] = {.lex_state = 949},
  [30] = {.lex_state = 949},
  [31] = {.lex_state = 1},
  [32] = {.lex_state = 1},
  [33] = {.lex_state = 1},
  [34] = {.lex_state = 0},
  [35] = {.lex_state = 0},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 0},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 949},
  [52] = {.lex_state = 949},
  [53] = {.lex_state = 0},
  [54] = {.lex_state = 0},
  [55] = {.lex_state = 0},
  [56] = {.lex_state = 0},
  [57] = {.lex_state = 0},
  [58] = {.lex_state = 0},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 0},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 0},
  [64] = {.lex_state = 0},
  [65] = {.lex_state = 0},
  [66] = {.lex_state = 0},
  [67] = {.lex_state = 1},
  [68] = {.lex_state = 1},
  [69] = {.lex_state = 1},
  [70] = {.lex_state = 1},
  [71] = {.lex_state = 1},
  [72] = {.lex_state = 1},
  [73] = {.lex_state = 1},
  [74] = {.lex_state = 1},
  [75] = {.lex_state = 1},
  [76] = {.lex_state = 1},
  [77] = {.lex_state = 1},
  [78] = {.lex_state = 1},
  [79] = {.lex_state = 1},
  [80] = {.lex_state = 1},
  [81] = {.lex_state = 949},
  [82] = {.lex_state = 949},
  [83] = {.lex_state = 0},
  [84] = {.lex_state = 1},
  [85] = {.lex_state = 949},
  [86] = {.lex_state = 1},
  [87] = {.lex_state = 949},
  [88] = {.lex_state = 1},
  [89] = {.lex_state = 1},
  [90] = {.lex_state = 1},
  [91] = {.lex_state = 1},
  [92] = {.lex_state = 949},
  [93] = {.lex_state = 1},
  [94] = {.lex_state = 1},
  [95] = {.lex_state = 1},
  [96] = {.lex_state = 949},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 1},
  [99] = {.lex_state = 1},
  [100] = {.lex_state = 1},
  [101] = {.lex_state = 1},
  [102] = {.lex_state = 1},
  [103] = {.lex_state = 0},
  [104] = {.lex_state = 1},
  [105] = {.lex_state = 0},
  [106] = {.lex_state = 0},
  [107] = {.lex_state = 1},
  [108] = {.lex_state = 0},
  [109] = {.lex_state = 0},
  [110] = {.lex_state = 0},
  [111] = {.lex_state = 0},
  [112] = {.lex_state = 0},
  [113] = {.lex_state = 0},
  [114] = {.lex_state = 0},
  [115] = {.lex_state = 0},
  [116] = {.lex_state = 0},
  [117] = {.lex_state = 0},
  [118] = {.lex_state = 0},
  [119] = {.lex_state = 0},
  [120] = {.lex_state = 0},
  [121] = {.lex_state = 0},
  [122] = {.lex_state = 0},
  [123] = {.lex_state = 0},
  [124] = {.lex_state = 0},
  [125] = {.lex_state = 0},
  [126] = {.lex_state = 0},
  [127] = {.lex_state = 0},
  [128] = {.lex_state = 0},
  [129] = {.lex_state = 0},
  [130] = {.lex_state = 0},
  [131] = {.lex_state = 0},
  [132] = {.lex_state = 949},
  [133] = {.lex_state = 0},
  [134] = {.lex_state = 0},
  [135] = {.lex_state = 0},
  [136] = {.lex_state = 0},
  [137] = {.lex_state = 0},
  [138] = {.lex_state = 949},
  [139] = {.lex_state = 0},
  [140] = {.lex_state = 949},
  [141] = {.lex_state = 949},
  [142] = {.lex_state = 0},
  [143] = {.lex_state = 0},
  [144] = {.lex_state = 0},
  [145] = {.lex_state = 0},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 0},
  [152] = {.lex_state = 3},
  [153] = {.lex_state = 949},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 0},
  [156] = {.lex_state = 0},
  [157] = {.lex_state = 0},
  [158] = {.lex_state = 0},
  [159] = {.lex_state = 949},
  [160] = {.lex_state = 1},
  [161] = {.lex_state = 1},
  [162] = {.lex_state = 0},
  [163] = {.lex_state = 0},
  [164] = {.lex_state = 0},
  [165] = {.lex_state = 0},
  [166] = {.lex_state = 949},
  [167] = {.lex_state = 0},
  [168] = {.lex_state = 0},
  [169] = {.lex_state = 0},
  [170] = {.lex_state = 1},
  [171] = {.lex_state = 1},
  [172] = {.lex_state = 0},
  [173] = {.lex_state = 0},
  [174] = {.lex_state = 0},
  [175] = {.lex_state = 0},
  [176] = {.lex_state = 0},
  [177] = {.lex_state = 0},
  [178] = {.lex_state = 1},
  [179] = {.lex_state = 0},
  [180] = {.lex_state = 949},
  [181] = {.lex_state = 949},
  [182] = {.lex_state = 949},
  [183] = {.lex_state = 949},
  [184] = {.lex_state = 949},
  [185] = {.lex_state = 0},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 0},
  [188] = {.lex_state = 949},
  [189] = {.lex_state = 949},
  [190] = {.lex_state = 949},
  [191] = {.lex_state = 949},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 0},
  [194] = {.lex_state = 0},
  [195] = {.lex_state = 0},
  [196] = {.lex_state = 949},
  [197] = {.lex_state = 949},
  [198] = {.lex_state = 949},
  [199] = {.lex_state = 0},
  [200] = {.lex_state = 0},
  [201] = {.lex_state = 0},
  [202] = {.lex_state = 0},
  [203] = {.lex_state = 0},
  [204] = {.lex_state = 0},
  [205] = {.lex_state = 0},
  [206] = {.lex_state = 0},
  [207] = {.lex_state = 0},
  [208] = {.lex_state = 0},
  [209] = {.lex_state = 0},
  [210] = {.lex_state = 0},
  [211] = {.lex_state = 0},
  [212] = {.lex_state = 0},
  [213] = {.lex_state = 0},
  [214] = {.lex_state = 0},
  [215] = {.lex_state = 0},
  [216] = {.lex_state = 0},
  [217] = {.lex_state = 949},
  [218] = {.lex_state = 0},
  [219] = {.lex_state = 0},
  [220] = {.lex_state = 0},
  [221] = {.lex_state = 0},
  [222] = {.lex_state = 0},
  [223] = {.lex_state = 0},
  [224] = {.lex_state = 0},
  [225] = {.lex_state = 0},
  [226] = {.lex_state = 0},
  [227] = {.lex_state = 0},
  [228] = {.lex_state = 0},
  [229] = {.lex_state = 0},
  [230] = {.lex_state = 0},
  [231] = {.lex_state = 0},
  [232] = {.lex_state = 0},
  [233] = {.lex_state = 0},
  [234] = {.lex_state = 0},
  [235] = {.lex_state = 0},
  [236] = {.lex_state = 949},
  [237] = {.lex_state = 0},
  [238] = {.lex_state = 0},
  [239] = {.lex_state = 0},
  [240] = {.lex_state = 0},
  [241] = {.lex_state = 0},
  [242] = {.lex_state = 0},
  [243] = {.lex_state = 0},
  [244] = {.lex_state = 0},
  [245] = {.lex_state = 0},
  [246] = {.lex_state = 0},
  [247] = {.lex_state = 0},
  [248] = {.lex_state = 0},
  [249] = {.lex_state = 0},
  [250] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_in] = ACTIONS(1),
    [anon_sym_AMP_AMP] = ACTIONS(1),
    [anon_sym_and] = ACTIONS(1),
    [anon_sym_xor] = ACTIONS(1),
    [anon_sym_CARET_CARET] = ACTIONS(1),
    [anon_sym_or] = ACTIONS(1),
    [anon_sym_PIPE_PIPE] = ACTIONS(1),
    [anon_sym_LBRACE] = ACTIONS(1),
    [anon_sym_RBRACE] = ACTIONS(1),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(1),
    [anon_sym_ne] = ACTIONS(1),
    [anon_sym_lt] = ACTIONS(1),
    [anon_sym_le] = ACTIONS(1),
    [anon_sym_gt] = ACTIONS(1),
    [anon_sym_ge] = ACTIONS(1),
    [anon_sym_EQ_EQ] = ACTIONS(1),
    [anon_sym_BANG_EQ] = ACTIONS(1),
    [anon_sym_LT] = ACTIONS(1),
    [anon_sym_LT_EQ] = ACTIONS(1),
    [anon_sym_GT] = ACTIONS(1),
    [anon_sym_GT_EQ] = ACTIONS(1),
    [anon_sym_contains] = ACTIONS(1),
    [anon_sym_matches] = ACTIONS(1),
    [anon_sym_TILDE] = ACTIONS(1),
    [anon_sym_concat] = ACTIONS(1),
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_COMMA] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [anon_sym_lookup_json_string] = ACTIONS(1),
    [anon_sym_lower] = ACTIONS(1),
    [anon_sym_regex_replace] = ACTIONS(1),
    [anon_sym_remove_bytes] = ACTIONS(1),
    [anon_sym_to_string] = ACTIONS(1),
    [anon_sym_upper] = ACTIONS(1),
    [anon_sym_url_decode] = ACTIONS(1),
    [anon_sym_uuidv4] = ACTIONS(1),
    [anon_sym_len] = ACTIONS(1),
    [anon_sym_ends_with] = ACTIONS(1),
    [anon_sym_starts_with] = ACTIONS(1),
    [anon_sym_any] = ACTIONS(1),
    [anon_sym_all] = ACTIONS(1),
    [anon_sym_LBRACK_STAR_RBRACK] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [aux_sym_ip_range_token1] = ACTIONS(1),
    [sym_ip_list] = ACTIONS(1),
    [anon_sym_not] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_LBRACK] = ACTIONS(1),
    [anon_sym_RBRACK] = ACTIONS(1),
    [anon_sym_STAR] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(1),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(1),
    [anon_sym_icmp_DOTtype] = ACTIONS(1),
    [anon_sym_icmp_DOTcode] = ACTIONS(1),
    [anon_sym_ip_DOThdr_len] = ACTIONS(1),
    [anon_sym_ip_DOTlen] = ACTIONS(1),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(1),
    [anon_sym_ip_DOTttl] = ACTIONS(1),
    [anon_sym_tcp_DOTflags] = ACTIONS(1),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(1),
    [anon_sym_tcp_DOTdstport] = ACTIONS(1),
    [anon_sym_udp_DOTdstport] = ACTIONS(1),
    [anon_sym_udp_DOTsrcport] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(1),
    [anon_sym_ip_DOTdst] = ACTIONS(1),
    [anon_sym_http_DOTcookie] = ACTIONS(1),
    [anon_sym_http_DOThost] = ACTIONS(1),
    [anon_sym_http_DOTreferer] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_http_DOTuser_agent] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(1),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(1),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(1),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(1),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(1),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(1),
    [anon_sym_icmp] = ACTIONS(1),
    [anon_sym_ip] = ACTIONS(1),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(1),
    [anon_sym_tcp] = ACTIONS(1),
    [anon_sym_udp] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(1),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(1),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(1),
    [anon_sym_ssl] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(1),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(1),
    [anon_sym_sip] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(193),
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(29),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [2] = {
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(29),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(55),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(57),
    [anon_sym_LPAREN] = ACTIONS(60),
    [anon_sym_lookup_json_string] = ACTIONS(63),
    [anon_sym_lower] = ACTIONS(66),
    [anon_sym_regex_replace] = ACTIONS(69),
    [anon_sym_remove_bytes] = ACTIONS(72),
    [anon_sym_to_string] = ACTIONS(75),
    [anon_sym_upper] = ACTIONS(66),
    [anon_sym_url_decode] = ACTIONS(66),
    [anon_sym_uuidv4] = ACTIONS(78),
    [anon_sym_len] = ACTIONS(81),
    [anon_sym_ends_with] = ACTIONS(84),
    [anon_sym_starts_with] = ACTIONS(84),
    [anon_sym_any] = ACTIONS(87),
    [anon_sym_all] = ACTIONS(87),
    [anon_sym_true] = ACTIONS(90),
    [anon_sym_false] = ACTIONS(90),
    [anon_sym_not] = ACTIONS(93),
    [anon_sym_BANG] = ACTIONS(93),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(96),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(96),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(99),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(96),
    [anon_sym_icmp_DOTtype] = ACTIONS(96),
    [anon_sym_icmp_DOTcode] = ACTIONS(96),
    [anon_sym_ip_DOThdr_len] = ACTIONS(96),
    [anon_sym_ip_DOTlen] = ACTIONS(96),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(96),
    [anon_sym_ip_DOTttl] = ACTIONS(96),
    [anon_sym_tcp_DOTflags] = ACTIONS(99),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(96),
    [anon_sym_tcp_DOTdstport] = ACTIONS(96),
    [anon_sym_udp_DOTdstport] = ACTIONS(96),
    [anon_sym_udp_DOTsrcport] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(96),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(96),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(96),
    [anon_sym_ip_DOTsrc] = ACTIONS(102),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(105),
    [anon_sym_ip_DOTdst] = ACTIONS(102),
    [anon_sym_http_DOTcookie] = ACTIONS(108),
    [anon_sym_http_DOThost] = ACTIONS(108),
    [anon_sym_http_DOTreferer] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(111),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_http_DOTuser_agent] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(108),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(111),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(108),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(108),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(108),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(108),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(108),
    [anon_sym_icmp] = ACTIONS(111),
    [anon_sym_ip] = ACTIONS(111),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(108),
    [anon_sym_tcp] = ACTIONS(111),
    [anon_sym_udp] = ACTIONS(111),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(108),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(114),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(117),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(117),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(123),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(126),
    [anon_sym_ssl] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(126),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(126),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(126),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(126),
    [anon_sym_sip] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(126),
  },
  [3] = {
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(29),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(129),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [4] = {
    [sym__expression] = STATE(28),
    [sym_not_expression] = STATE(28),
    [sym_in_expression] = STATE(28),
    [sym_compound_expression] = STATE(28),
    [sym_simple_expression] = STATE(28),
    [sym__bool_lhs] = STATE(28),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(28),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(28),
    [sym_boolean] = STATE(28),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(28),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [5] = {
    [sym__expression] = STATE(23),
    [sym_not_expression] = STATE(23),
    [sym_in_expression] = STATE(23),
    [sym_compound_expression] = STATE(23),
    [sym_simple_expression] = STATE(23),
    [sym__bool_lhs] = STATE(23),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(23),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(23),
    [sym_boolean] = STATE(23),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(23),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [6] = {
    [sym__expression] = STATE(83),
    [sym_not_expression] = STATE(83),
    [sym_in_expression] = STATE(83),
    [sym_compound_expression] = STATE(83),
    [sym_simple_expression] = STATE(83),
    [sym__bool_lhs] = STATE(83),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(83),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(83),
    [sym_boolean] = STATE(83),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(83),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [7] = {
    [sym__expression] = STATE(21),
    [sym_not_expression] = STATE(21),
    [sym_in_expression] = STATE(21),
    [sym_compound_expression] = STATE(21),
    [sym_simple_expression] = STATE(21),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(21),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(21),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(21),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [8] = {
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_in_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym_simple_expression] = STATE(13),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(79),
    [sym__string_lhs] = STATE(67),
    [sym_string_func] = STATE(67),
    [sym_number_func] = STATE(79),
    [sym_bool_func] = STATE(13),
    [sym_array_func] = STATE(26),
    [sym_group] = STATE(13),
    [sym_boolean] = STATE(13),
    [sym_not_operator] = STATE(8),
    [sym_number_array] = STATE(191),
    [sym_bool_array] = STATE(189),
    [sym_string_array] = STATE(183),
    [sym_boollike_field] = STATE(13),
    [sym_numberlike_field] = STATE(79),
    [sym_stringlike_field] = STATE(67),
    [sym_number_field] = STATE(75),
    [sym_ip_field] = STATE(86),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [sym_array_number_field] = STATE(180),
    [sym_bool_field] = STATE(19),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [anon_sym_RBRACE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_any] = ACTIONS(131),
    [anon_sym_all] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [sym_ipv4] = ACTIONS(131),
    [anon_sym_SLASH] = ACTIONS(133),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(135),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_icmp_DOTtype] = ACTIONS(131),
    [anon_sym_icmp_DOTcode] = ACTIONS(131),
    [anon_sym_ip_DOThdr_len] = ACTIONS(131),
    [anon_sym_ip_DOTlen] = ACTIONS(131),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(131),
    [anon_sym_ip_DOTttl] = ACTIONS(131),
    [anon_sym_tcp_DOTflags] = ACTIONS(135),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(131),
    [anon_sym_tcp_DOTdstport] = ACTIONS(131),
    [anon_sym_udp_DOTdstport] = ACTIONS(131),
    [anon_sym_udp_DOTsrcport] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(135),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_ip_DOTdst] = ACTIONS(135),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(131),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(131),
    [anon_sym_icmp] = ACTIONS(135),
    [anon_sym_ip] = ACTIONS(135),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(131),
    [anon_sym_tcp] = ACTIONS(135),
    [anon_sym_udp] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(131),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(135),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_sip] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(131),
  },
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(137),
    [anon_sym_AMP_AMP] = ACTIONS(137),
    [anon_sym_and] = ACTIONS(137),
    [anon_sym_xor] = ACTIONS(137),
    [anon_sym_CARET_CARET] = ACTIONS(137),
    [anon_sym_or] = ACTIONS(137),
    [anon_sym_PIPE_PIPE] = ACTIONS(137),
    [anon_sym_RBRACE] = ACTIONS(137),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(137),
    [anon_sym_LPAREN] = ACTIONS(137),
    [anon_sym_RPAREN] = ACTIONS(137),
    [anon_sym_lookup_json_string] = ACTIONS(137),
    [anon_sym_lower] = ACTIONS(137),
    [anon_sym_regex_replace] = ACTIONS(137),
    [anon_sym_remove_bytes] = ACTIONS(137),
    [anon_sym_to_string] = ACTIONS(137),
    [anon_sym_upper] = ACTIONS(137),
    [anon_sym_url_decode] = ACTIONS(137),
    [anon_sym_uuidv4] = ACTIONS(137),
    [anon_sym_len] = ACTIONS(137),
    [anon_sym_ends_with] = ACTIONS(137),
    [anon_sym_starts_with] = ACTIONS(137),
    [anon_sym_any] = ACTIONS(137),
    [anon_sym_all] = ACTIONS(137),
    [anon_sym_true] = ACTIONS(137),
    [anon_sym_false] = ACTIONS(137),
    [sym_ipv4] = ACTIONS(137),
    [anon_sym_not] = ACTIONS(137),
    [anon_sym_BANG] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(137),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(137),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(139),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(137),
    [anon_sym_icmp_DOTtype] = ACTIONS(137),
    [anon_sym_icmp_DOTcode] = ACTIONS(137),
    [anon_sym_ip_DOThdr_len] = ACTIONS(137),
    [anon_sym_ip_DOTlen] = ACTIONS(137),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(137),
    [anon_sym_ip_DOTttl] = ACTIONS(137),
    [anon_sym_tcp_DOTflags] = ACTIONS(139),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(137),
    [anon_sym_tcp_DOTdstport] = ACTIONS(137),
    [anon_sym_udp_DOTdstport] = ACTIONS(137),
    [anon_sym_udp_DOTsrcport] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc] = ACTIONS(139),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(137),
    [anon_sym_ip_DOTdst] = ACTIONS(139),
    [anon_sym_http_DOTcookie] = ACTIONS(137),
    [anon_sym_http_DOThost] = ACTIONS(137),
    [anon_sym_http_DOTreferer] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(137),
    [anon_sym_http_DOTuser_agent] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(137),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(137),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(137),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(137),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(137),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(137),
    [anon_sym_icmp] = ACTIONS(139),
    [anon_sym_ip] = ACTIONS(139),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(137),
    [anon_sym_tcp] = ACTIONS(139),
    [anon_sym_udp] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(137),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(139),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(137),
    [anon_sym_ssl] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(137),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(137),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(137),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(137),
    [anon_sym_sip] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(137),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(141),
    [anon_sym_AMP_AMP] = ACTIONS(141),
    [anon_sym_and] = ACTIONS(141),
    [anon_sym_xor] = ACTIONS(141),
    [anon_sym_CARET_CARET] = ACTIONS(141),
    [anon_sym_or] = ACTIONS(141),
    [anon_sym_PIPE_PIPE] = ACTIONS(141),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(141),
    [anon_sym_LPAREN] = ACTIONS(141),
    [anon_sym_RPAREN] = ACTIONS(141),
    [anon_sym_lookup_json_string] = ACTIONS(141),
    [anon_sym_lower] = ACTIONS(141),
    [anon_sym_regex_replace] = ACTIONS(141),
    [anon_sym_remove_bytes] = ACTIONS(141),
    [anon_sym_to_string] = ACTIONS(141),
    [anon_sym_upper] = ACTIONS(141),
    [anon_sym_url_decode] = ACTIONS(141),
    [anon_sym_uuidv4] = ACTIONS(141),
    [anon_sym_len] = ACTIONS(141),
    [anon_sym_ends_with] = ACTIONS(141),
    [anon_sym_starts_with] = ACTIONS(141),
    [anon_sym_any] = ACTIONS(141),
    [anon_sym_all] = ACTIONS(141),
    [anon_sym_true] = ACTIONS(141),
    [anon_sym_false] = ACTIONS(141),
    [anon_sym_not] = ACTIONS(141),
    [anon_sym_BANG] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(141),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(141),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(143),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(141),
    [anon_sym_icmp_DOTtype] = ACTIONS(141),
    [anon_sym_icmp_DOTcode] = ACTIONS(141),
    [anon_sym_ip_DOThdr_len] = ACTIONS(141),
    [anon_sym_ip_DOTlen] = ACTIONS(141),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(141),
    [anon_sym_ip_DOTttl] = ACTIONS(141),
    [anon_sym_tcp_DOTflags] = ACTIONS(143),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(141),
    [anon_sym_tcp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTsrcport] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc] = ACTIONS(143),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(141),
    [anon_sym_ip_DOTdst] = ACTIONS(143),
    [anon_sym_http_DOTcookie] = ACTIONS(141),
    [anon_sym_http_DOThost] = ACTIONS(141),
    [anon_sym_http_DOTreferer] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_http_DOTuser_agent] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(141),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(143),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(141),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(141),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(141),
    [anon_sym_icmp] = ACTIONS(143),
    [anon_sym_ip] = ACTIONS(143),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(141),
    [anon_sym_tcp] = ACTIONS(143),
    [anon_sym_udp] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(141),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(143),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(143),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(141),
    [anon_sym_ssl] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(141),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(141),
    [anon_sym_sip] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(141),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(145),
    [anon_sym_AMP_AMP] = ACTIONS(145),
    [anon_sym_and] = ACTIONS(145),
    [anon_sym_xor] = ACTIONS(145),
    [anon_sym_CARET_CARET] = ACTIONS(145),
    [anon_sym_or] = ACTIONS(145),
    [anon_sym_PIPE_PIPE] = ACTIONS(145),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(145),
    [anon_sym_LPAREN] = ACTIONS(145),
    [anon_sym_RPAREN] = ACTIONS(145),
    [anon_sym_lookup_json_string] = ACTIONS(145),
    [anon_sym_lower] = ACTIONS(145),
    [anon_sym_regex_replace] = ACTIONS(145),
    [anon_sym_remove_bytes] = ACTIONS(145),
    [anon_sym_to_string] = ACTIONS(145),
    [anon_sym_upper] = ACTIONS(145),
    [anon_sym_url_decode] = ACTIONS(145),
    [anon_sym_uuidv4] = ACTIONS(145),
    [anon_sym_len] = ACTIONS(145),
    [anon_sym_ends_with] = ACTIONS(145),
    [anon_sym_starts_with] = ACTIONS(145),
    [anon_sym_any] = ACTIONS(145),
    [anon_sym_all] = ACTIONS(145),
    [anon_sym_true] = ACTIONS(145),
    [anon_sym_false] = ACTIONS(145),
    [anon_sym_not] = ACTIONS(145),
    [anon_sym_BANG] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(145),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(145),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(145),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(145),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(145),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(145),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(145),
    [anon_sym_icmp_DOTtype] = ACTIONS(145),
    [anon_sym_icmp_DOTcode] = ACTIONS(145),
    [anon_sym_ip_DOThdr_len] = ACTIONS(145),
    [anon_sym_ip_DOTlen] = ACTIONS(145),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(145),
    [anon_sym_ip_DOTttl] = ACTIONS(145),
    [anon_sym_tcp_DOTflags] = ACTIONS(147),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(145),
    [anon_sym_tcp_DOTdstport] = ACTIONS(145),
    [anon_sym_udp_DOTdstport] = ACTIONS(145),
    [anon_sym_udp_DOTsrcport] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(145),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(145),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(145),
    [anon_sym_ip_DOTsrc] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(145),
    [anon_sym_ip_DOTdst] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(145),
    [anon_sym_http_DOThost] = ACTIONS(145),
    [anon_sym_http_DOTreferer] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(145),
    [anon_sym_http_DOTuser_agent] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(145),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(145),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(145),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(145),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(145),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(145),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(145),
    [anon_sym_icmp] = ACTIONS(147),
    [anon_sym_ip] = ACTIONS(147),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(145),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(145),
    [anon_sym_tcp] = ACTIONS(147),
    [anon_sym_udp] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(145),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(147),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(145),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(145),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(145),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(145),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(145),
    [anon_sym_ssl] = ACTIONS(145),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(145),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(145),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(145),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(145),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(145),
    [anon_sym_sip] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(145),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(145),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(149),
    [anon_sym_AMP_AMP] = ACTIONS(149),
    [anon_sym_and] = ACTIONS(149),
    [anon_sym_xor] = ACTIONS(149),
    [anon_sym_CARET_CARET] = ACTIONS(149),
    [anon_sym_or] = ACTIONS(149),
    [anon_sym_PIPE_PIPE] = ACTIONS(149),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(149),
    [anon_sym_LPAREN] = ACTIONS(149),
    [anon_sym_RPAREN] = ACTIONS(149),
    [anon_sym_lookup_json_string] = ACTIONS(149),
    [anon_sym_lower] = ACTIONS(149),
    [anon_sym_regex_replace] = ACTIONS(149),
    [anon_sym_remove_bytes] = ACTIONS(149),
    [anon_sym_to_string] = ACTIONS(149),
    [anon_sym_upper] = ACTIONS(149),
    [anon_sym_url_decode] = ACTIONS(149),
    [anon_sym_uuidv4] = ACTIONS(149),
    [anon_sym_len] = ACTIONS(149),
    [anon_sym_ends_with] = ACTIONS(149),
    [anon_sym_starts_with] = ACTIONS(149),
    [anon_sym_any] = ACTIONS(149),
    [anon_sym_all] = ACTIONS(149),
    [anon_sym_true] = ACTIONS(149),
    [anon_sym_false] = ACTIONS(149),
    [anon_sym_not] = ACTIONS(149),
    [anon_sym_BANG] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(149),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(149),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(149),
    [anon_sym_icmp_DOTtype] = ACTIONS(149),
    [anon_sym_icmp_DOTcode] = ACTIONS(149),
    [anon_sym_ip_DOThdr_len] = ACTIONS(149),
    [anon_sym_ip_DOTlen] = ACTIONS(149),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(149),
    [anon_sym_ip_DOTttl] = ACTIONS(149),
    [anon_sym_tcp_DOTflags] = ACTIONS(151),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(149),
    [anon_sym_tcp_DOTdstport] = ACTIONS(149),
    [anon_sym_udp_DOTdstport] = ACTIONS(149),
    [anon_sym_udp_DOTsrcport] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc] = ACTIONS(151),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(149),
    [anon_sym_ip_DOTdst] = ACTIONS(151),
    [anon_sym_http_DOTcookie] = ACTIONS(149),
    [anon_sym_http_DOThost] = ACTIONS(149),
    [anon_sym_http_DOTreferer] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(149),
    [anon_sym_http_DOTuser_agent] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(149),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(149),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(149),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(149),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(149),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(149),
    [anon_sym_icmp] = ACTIONS(151),
    [anon_sym_ip] = ACTIONS(151),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(149),
    [anon_sym_tcp] = ACTIONS(151),
    [anon_sym_udp] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(149),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(151),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(149),
    [anon_sym_ssl] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(149),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(149),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(149),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(149),
    [anon_sym_sip] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(149),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(153),
    [anon_sym_AMP_AMP] = ACTIONS(153),
    [anon_sym_and] = ACTIONS(153),
    [anon_sym_xor] = ACTIONS(153),
    [anon_sym_CARET_CARET] = ACTIONS(153),
    [anon_sym_or] = ACTIONS(153),
    [anon_sym_PIPE_PIPE] = ACTIONS(153),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(153),
    [anon_sym_LPAREN] = ACTIONS(153),
    [anon_sym_RPAREN] = ACTIONS(153),
    [anon_sym_lookup_json_string] = ACTIONS(153),
    [anon_sym_lower] = ACTIONS(153),
    [anon_sym_regex_replace] = ACTIONS(153),
    [anon_sym_remove_bytes] = ACTIONS(153),
    [anon_sym_to_string] = ACTIONS(153),
    [anon_sym_upper] = ACTIONS(153),
    [anon_sym_url_decode] = ACTIONS(153),
    [anon_sym_uuidv4] = ACTIONS(153),
    [anon_sym_len] = ACTIONS(153),
    [anon_sym_ends_with] = ACTIONS(153),
    [anon_sym_starts_with] = ACTIONS(153),
    [anon_sym_any] = ACTIONS(153),
    [anon_sym_all] = ACTIONS(153),
    [anon_sym_true] = ACTIONS(153),
    [anon_sym_false] = ACTIONS(153),
    [anon_sym_not] = ACTIONS(153),
    [anon_sym_BANG] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(153),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(153),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(153),
    [anon_sym_icmp_DOTtype] = ACTIONS(153),
    [anon_sym_icmp_DOTcode] = ACTIONS(153),
    [anon_sym_ip_DOThdr_len] = ACTIONS(153),
    [anon_sym_ip_DOTlen] = ACTIONS(153),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(153),
    [anon_sym_ip_DOTttl] = ACTIONS(153),
    [anon_sym_tcp_DOTflags] = ACTIONS(155),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(153),
    [anon_sym_tcp_DOTdstport] = ACTIONS(153),
    [anon_sym_udp_DOTdstport] = ACTIONS(153),
    [anon_sym_udp_DOTsrcport] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc] = ACTIONS(155),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(153),
    [anon_sym_ip_DOTdst] = ACTIONS(155),
    [anon_sym_http_DOTcookie] = ACTIONS(153),
    [anon_sym_http_DOThost] = ACTIONS(153),
    [anon_sym_http_DOTreferer] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_http_DOTuser_agent] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(153),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(153),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(153),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(153),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(153),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(153),
    [anon_sym_icmp] = ACTIONS(155),
    [anon_sym_ip] = ACTIONS(155),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(153),
    [anon_sym_tcp] = ACTIONS(155),
    [anon_sym_udp] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(153),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(155),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(153),
    [anon_sym_ssl] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(153),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(153),
    [anon_sym_sip] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(153),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(157),
    [anon_sym_AMP_AMP] = ACTIONS(157),
    [anon_sym_and] = ACTIONS(157),
    [anon_sym_xor] = ACTIONS(157),
    [anon_sym_CARET_CARET] = ACTIONS(157),
    [anon_sym_or] = ACTIONS(157),
    [anon_sym_PIPE_PIPE] = ACTIONS(157),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(157),
    [anon_sym_LPAREN] = ACTIONS(157),
    [anon_sym_RPAREN] = ACTIONS(157),
    [anon_sym_lookup_json_string] = ACTIONS(157),
    [anon_sym_lower] = ACTIONS(157),
    [anon_sym_regex_replace] = ACTIONS(157),
    [anon_sym_remove_bytes] = ACTIONS(157),
    [anon_sym_to_string] = ACTIONS(157),
    [anon_sym_upper] = ACTIONS(157),
    [anon_sym_url_decode] = ACTIONS(157),
    [anon_sym_uuidv4] = ACTIONS(157),
    [anon_sym_len] = ACTIONS(157),
    [anon_sym_ends_with] = ACTIONS(157),
    [anon_sym_starts_with] = ACTIONS(157),
    [anon_sym_any] = ACTIONS(157),
    [anon_sym_all] = ACTIONS(157),
    [anon_sym_true] = ACTIONS(157),
    [anon_sym_false] = ACTIONS(157),
    [anon_sym_not] = ACTIONS(157),
    [anon_sym_BANG] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(157),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(157),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(159),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(157),
    [anon_sym_icmp_DOTtype] = ACTIONS(157),
    [anon_sym_icmp_DOTcode] = ACTIONS(157),
    [anon_sym_ip_DOThdr_len] = ACTIONS(157),
    [anon_sym_ip_DOTlen] = ACTIONS(157),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(157),
    [anon_sym_ip_DOTttl] = ACTIONS(157),
    [anon_sym_tcp_DOTflags] = ACTIONS(159),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(157),
    [anon_sym_tcp_DOTdstport] = ACTIONS(157),
    [anon_sym_udp_DOTdstport] = ACTIONS(157),
    [anon_sym_udp_DOTsrcport] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc] = ACTIONS(159),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(157),
    [anon_sym_ip_DOTdst] = ACTIONS(159),
    [anon_sym_http_DOTcookie] = ACTIONS(157),
    [anon_sym_http_DOThost] = ACTIONS(157),
    [anon_sym_http_DOTreferer] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(157),
    [anon_sym_http_DOTuser_agent] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(157),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(157),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(157),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(157),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(157),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(157),
    [anon_sym_icmp] = ACTIONS(159),
    [anon_sym_ip] = ACTIONS(159),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(157),
    [anon_sym_tcp] = ACTIONS(159),
    [anon_sym_udp] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(157),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(159),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(157),
    [anon_sym_ssl] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(157),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(157),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(157),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(157),
    [anon_sym_sip] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(157),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(161),
    [anon_sym_AMP_AMP] = ACTIONS(161),
    [anon_sym_and] = ACTIONS(161),
    [anon_sym_xor] = ACTIONS(161),
    [anon_sym_CARET_CARET] = ACTIONS(161),
    [anon_sym_or] = ACTIONS(161),
    [anon_sym_PIPE_PIPE] = ACTIONS(161),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(161),
    [anon_sym_LPAREN] = ACTIONS(161),
    [anon_sym_RPAREN] = ACTIONS(161),
    [anon_sym_lookup_json_string] = ACTIONS(161),
    [anon_sym_lower] = ACTIONS(161),
    [anon_sym_regex_replace] = ACTIONS(161),
    [anon_sym_remove_bytes] = ACTIONS(161),
    [anon_sym_to_string] = ACTIONS(161),
    [anon_sym_upper] = ACTIONS(161),
    [anon_sym_url_decode] = ACTIONS(161),
    [anon_sym_uuidv4] = ACTIONS(161),
    [anon_sym_len] = ACTIONS(161),
    [anon_sym_ends_with] = ACTIONS(161),
    [anon_sym_starts_with] = ACTIONS(161),
    [anon_sym_any] = ACTIONS(161),
    [anon_sym_all] = ACTIONS(161),
    [anon_sym_true] = ACTIONS(161),
    [anon_sym_false] = ACTIONS(161),
    [anon_sym_not] = ACTIONS(161),
    [anon_sym_BANG] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(161),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(161),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(161),
    [anon_sym_icmp_DOTtype] = ACTIONS(161),
    [anon_sym_icmp_DOTcode] = ACTIONS(161),
    [anon_sym_ip_DOThdr_len] = ACTIONS(161),
    [anon_sym_ip_DOTlen] = ACTIONS(161),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(161),
    [anon_sym_ip_DOTttl] = ACTIONS(161),
    [anon_sym_tcp_DOTflags] = ACTIONS(163),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(161),
    [anon_sym_tcp_DOTdstport] = ACTIONS(161),
    [anon_sym_udp_DOTdstport] = ACTIONS(161),
    [anon_sym_udp_DOTsrcport] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(161),
    [anon_sym_ip_DOTdst] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(161),
    [anon_sym_http_DOThost] = ACTIONS(161),
    [anon_sym_http_DOTreferer] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(161),
    [anon_sym_http_DOTuser_agent] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(161),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(161),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(161),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(161),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(161),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(161),
    [anon_sym_icmp] = ACTIONS(163),
    [anon_sym_ip] = ACTIONS(163),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(161),
    [anon_sym_tcp] = ACTIONS(163),
    [anon_sym_udp] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(161),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(163),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(161),
    [anon_sym_ssl] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(161),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(161),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(161),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(161),
    [anon_sym_sip] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(161),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(165),
    [anon_sym_AMP_AMP] = ACTIONS(165),
    [anon_sym_and] = ACTIONS(165),
    [anon_sym_xor] = ACTIONS(165),
    [anon_sym_CARET_CARET] = ACTIONS(165),
    [anon_sym_or] = ACTIONS(165),
    [anon_sym_PIPE_PIPE] = ACTIONS(165),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(165),
    [anon_sym_LPAREN] = ACTIONS(165),
    [anon_sym_RPAREN] = ACTIONS(165),
    [anon_sym_lookup_json_string] = ACTIONS(165),
    [anon_sym_lower] = ACTIONS(165),
    [anon_sym_regex_replace] = ACTIONS(165),
    [anon_sym_remove_bytes] = ACTIONS(165),
    [anon_sym_to_string] = ACTIONS(165),
    [anon_sym_upper] = ACTIONS(165),
    [anon_sym_url_decode] = ACTIONS(165),
    [anon_sym_uuidv4] = ACTIONS(165),
    [anon_sym_len] = ACTIONS(165),
    [anon_sym_ends_with] = ACTIONS(165),
    [anon_sym_starts_with] = ACTIONS(165),
    [anon_sym_any] = ACTIONS(165),
    [anon_sym_all] = ACTIONS(165),
    [anon_sym_true] = ACTIONS(165),
    [anon_sym_false] = ACTIONS(165),
    [anon_sym_not] = ACTIONS(165),
    [anon_sym_BANG] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(165),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(165),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(165),
    [anon_sym_icmp_DOTtype] = ACTIONS(165),
    [anon_sym_icmp_DOTcode] = ACTIONS(165),
    [anon_sym_ip_DOThdr_len] = ACTIONS(165),
    [anon_sym_ip_DOTlen] = ACTIONS(165),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(165),
    [anon_sym_ip_DOTttl] = ACTIONS(165),
    [anon_sym_tcp_DOTflags] = ACTIONS(167),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(165),
    [anon_sym_tcp_DOTdstport] = ACTIONS(165),
    [anon_sym_udp_DOTdstport] = ACTIONS(165),
    [anon_sym_udp_DOTsrcport] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(165),
    [anon_sym_ip_DOTdst] = ACTIONS(167),
    [anon_sym_http_DOTcookie] = ACTIONS(165),
    [anon_sym_http_DOThost] = ACTIONS(165),
    [anon_sym_http_DOTreferer] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(165),
    [anon_sym_http_DOTuser_agent] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(165),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(165),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(165),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(165),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(165),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(165),
    [anon_sym_icmp] = ACTIONS(167),
    [anon_sym_ip] = ACTIONS(167),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(165),
    [anon_sym_tcp] = ACTIONS(167),
    [anon_sym_udp] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(165),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(167),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(165),
    [anon_sym_ssl] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(165),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(165),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(165),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(165),
    [anon_sym_sip] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(165),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_any] = ACTIONS(169),
    [anon_sym_all] = ACTIONS(169),
    [anon_sym_true] = ACTIONS(169),
    [anon_sym_false] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(171),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(171),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(171),
    [anon_sym_ip] = ACTIONS(171),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(171),
    [anon_sym_udp] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(171),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_sip] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(169),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(173),
    [anon_sym_AMP_AMP] = ACTIONS(173),
    [anon_sym_and] = ACTIONS(173),
    [anon_sym_xor] = ACTIONS(173),
    [anon_sym_CARET_CARET] = ACTIONS(173),
    [anon_sym_or] = ACTIONS(173),
    [anon_sym_PIPE_PIPE] = ACTIONS(173),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(173),
    [anon_sym_LPAREN] = ACTIONS(173),
    [anon_sym_RPAREN] = ACTIONS(173),
    [anon_sym_lookup_json_string] = ACTIONS(173),
    [anon_sym_lower] = ACTIONS(173),
    [anon_sym_regex_replace] = ACTIONS(173),
    [anon_sym_remove_bytes] = ACTIONS(173),
    [anon_sym_to_string] = ACTIONS(173),
    [anon_sym_upper] = ACTIONS(173),
    [anon_sym_url_decode] = ACTIONS(173),
    [anon_sym_uuidv4] = ACTIONS(173),
    [anon_sym_len] = ACTIONS(173),
    [anon_sym_ends_with] = ACTIONS(173),
    [anon_sym_starts_with] = ACTIONS(173),
    [anon_sym_any] = ACTIONS(173),
    [anon_sym_all] = ACTIONS(173),
    [anon_sym_true] = ACTIONS(173),
    [anon_sym_false] = ACTIONS(173),
    [anon_sym_not] = ACTIONS(173),
    [anon_sym_BANG] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(173),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(173),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(175),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(173),
    [anon_sym_icmp_DOTtype] = ACTIONS(173),
    [anon_sym_icmp_DOTcode] = ACTIONS(173),
    [anon_sym_ip_DOThdr_len] = ACTIONS(173),
    [anon_sym_ip_DOTlen] = ACTIONS(173),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(173),
    [anon_sym_ip_DOTttl] = ACTIONS(173),
    [anon_sym_tcp_DOTflags] = ACTIONS(175),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(173),
    [anon_sym_tcp_DOTdstport] = ACTIONS(173),
    [anon_sym_udp_DOTdstport] = ACTIONS(173),
    [anon_sym_udp_DOTsrcport] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc] = ACTIONS(175),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(173),
    [anon_sym_ip_DOTdst] = ACTIONS(175),
    [anon_sym_http_DOTcookie] = ACTIONS(173),
    [anon_sym_http_DOThost] = ACTIONS(173),
    [anon_sym_http_DOTreferer] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(173),
    [anon_sym_http_DOTuser_agent] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(173),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(173),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(173),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(173),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(173),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(173),
    [anon_sym_icmp] = ACTIONS(175),
    [anon_sym_ip] = ACTIONS(175),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(173),
    [anon_sym_tcp] = ACTIONS(175),
    [anon_sym_udp] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(173),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(175),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(173),
    [anon_sym_ssl] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(173),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(173),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(173),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(173),
    [anon_sym_sip] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(173),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(177),
    [anon_sym_AMP_AMP] = ACTIONS(177),
    [anon_sym_and] = ACTIONS(177),
    [anon_sym_xor] = ACTIONS(177),
    [anon_sym_CARET_CARET] = ACTIONS(177),
    [anon_sym_or] = ACTIONS(177),
    [anon_sym_PIPE_PIPE] = ACTIONS(177),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(177),
    [anon_sym_LPAREN] = ACTIONS(177),
    [anon_sym_RPAREN] = ACTIONS(177),
    [anon_sym_lookup_json_string] = ACTIONS(177),
    [anon_sym_lower] = ACTIONS(177),
    [anon_sym_regex_replace] = ACTIONS(177),
    [anon_sym_remove_bytes] = ACTIONS(177),
    [anon_sym_to_string] = ACTIONS(177),
    [anon_sym_upper] = ACTIONS(177),
    [anon_sym_url_decode] = ACTIONS(177),
    [anon_sym_uuidv4] = ACTIONS(177),
    [anon_sym_len] = ACTIONS(177),
    [anon_sym_ends_with] = ACTIONS(177),
    [anon_sym_starts_with] = ACTIONS(177),
    [anon_sym_any] = ACTIONS(177),
    [anon_sym_all] = ACTIONS(177),
    [anon_sym_true] = ACTIONS(177),
    [anon_sym_false] = ACTIONS(177),
    [anon_sym_not] = ACTIONS(177),
    [anon_sym_BANG] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(177),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(177),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(177),
    [anon_sym_icmp_DOTtype] = ACTIONS(177),
    [anon_sym_icmp_DOTcode] = ACTIONS(177),
    [anon_sym_ip_DOThdr_len] = ACTIONS(177),
    [anon_sym_ip_DOTlen] = ACTIONS(177),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(177),
    [anon_sym_ip_DOTttl] = ACTIONS(177),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(177),
    [anon_sym_tcp_DOTdstport] = ACTIONS(177),
    [anon_sym_udp_DOTdstport] = ACTIONS(177),
    [anon_sym_udp_DOTsrcport] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(177),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(177),
    [anon_sym_http_DOThost] = ACTIONS(177),
    [anon_sym_http_DOTreferer] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(177),
    [anon_sym_http_DOTuser_agent] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(177),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(177),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(177),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(177),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(177),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(177),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(177),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(177),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(177),
    [anon_sym_ssl] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(177),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(177),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(177),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(177),
    [anon_sym_sip] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(177),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(181),
    [anon_sym_AMP_AMP] = ACTIONS(181),
    [anon_sym_and] = ACTIONS(181),
    [anon_sym_xor] = ACTIONS(181),
    [anon_sym_CARET_CARET] = ACTIONS(181),
    [anon_sym_or] = ACTIONS(181),
    [anon_sym_PIPE_PIPE] = ACTIONS(181),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(181),
    [anon_sym_LPAREN] = ACTIONS(181),
    [anon_sym_RPAREN] = ACTIONS(181),
    [anon_sym_lookup_json_string] = ACTIONS(181),
    [anon_sym_lower] = ACTIONS(181),
    [anon_sym_regex_replace] = ACTIONS(181),
    [anon_sym_remove_bytes] = ACTIONS(181),
    [anon_sym_to_string] = ACTIONS(181),
    [anon_sym_upper] = ACTIONS(181),
    [anon_sym_url_decode] = ACTIONS(181),
    [anon_sym_uuidv4] = ACTIONS(181),
    [anon_sym_len] = ACTIONS(181),
    [anon_sym_ends_with] = ACTIONS(181),
    [anon_sym_starts_with] = ACTIONS(181),
    [anon_sym_any] = ACTIONS(181),
    [anon_sym_all] = ACTIONS(181),
    [anon_sym_true] = ACTIONS(181),
    [anon_sym_false] = ACTIONS(181),
    [anon_sym_not] = ACTIONS(181),
    [anon_sym_BANG] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(181),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(181),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(181),
    [anon_sym_icmp_DOTtype] = ACTIONS(181),
    [anon_sym_icmp_DOTcode] = ACTIONS(181),
    [anon_sym_ip_DOThdr_len] = ACTIONS(181),
    [anon_sym_ip_DOTlen] = ACTIONS(181),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(181),
    [anon_sym_ip_DOTttl] = ACTIONS(181),
    [anon_sym_tcp_DOTflags] = ACTIONS(183),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(181),
    [anon_sym_tcp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTsrcport] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc] = ACTIONS(183),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(181),
    [anon_sym_ip_DOTdst] = ACTIONS(183),
    [anon_sym_http_DOTcookie] = ACTIONS(181),
    [anon_sym_http_DOThost] = ACTIONS(181),
    [anon_sym_http_DOTreferer] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_http_DOTuser_agent] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(181),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(181),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(181),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(181),
    [anon_sym_icmp] = ACTIONS(183),
    [anon_sym_ip] = ACTIONS(183),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(181),
    [anon_sym_tcp] = ACTIONS(183),
    [anon_sym_udp] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(181),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(183),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(181),
    [anon_sym_ssl] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(181),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(181),
    [anon_sym_sip] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(181),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(185),
    [anon_sym_AMP_AMP] = ACTIONS(185),
    [anon_sym_and] = ACTIONS(185),
    [anon_sym_xor] = ACTIONS(185),
    [anon_sym_CARET_CARET] = ACTIONS(185),
    [anon_sym_or] = ACTIONS(185),
    [anon_sym_PIPE_PIPE] = ACTIONS(185),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(185),
    [anon_sym_LPAREN] = ACTIONS(185),
    [anon_sym_RPAREN] = ACTIONS(185),
    [anon_sym_lookup_json_string] = ACTIONS(185),
    [anon_sym_lower] = ACTIONS(185),
    [anon_sym_regex_replace] = ACTIONS(185),
    [anon_sym_remove_bytes] = ACTIONS(185),
    [anon_sym_to_string] = ACTIONS(185),
    [anon_sym_upper] = ACTIONS(185),
    [anon_sym_url_decode] = ACTIONS(185),
    [anon_sym_uuidv4] = ACTIONS(185),
    [anon_sym_len] = ACTIONS(185),
    [anon_sym_ends_with] = ACTIONS(185),
    [anon_sym_starts_with] = ACTIONS(185),
    [anon_sym_any] = ACTIONS(185),
    [anon_sym_all] = ACTIONS(185),
    [anon_sym_true] = ACTIONS(185),
    [anon_sym_false] = ACTIONS(185),
    [anon_sym_not] = ACTIONS(185),
    [anon_sym_BANG] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(185),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(185),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(185),
    [anon_sym_icmp_DOTtype] = ACTIONS(185),
    [anon_sym_icmp_DOTcode] = ACTIONS(185),
    [anon_sym_ip_DOThdr_len] = ACTIONS(185),
    [anon_sym_ip_DOTlen] = ACTIONS(185),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(185),
    [anon_sym_ip_DOTttl] = ACTIONS(185),
    [anon_sym_tcp_DOTflags] = ACTIONS(187),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(185),
    [anon_sym_tcp_DOTdstport] = ACTIONS(185),
    [anon_sym_udp_DOTdstport] = ACTIONS(185),
    [anon_sym_udp_DOTsrcport] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(185),
    [anon_sym_ip_DOTdst] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(185),
    [anon_sym_http_DOThost] = ACTIONS(185),
    [anon_sym_http_DOTreferer] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(185),
    [anon_sym_http_DOTuser_agent] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(185),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(185),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(185),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(185),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(185),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(185),
    [anon_sym_icmp] = ACTIONS(187),
    [anon_sym_ip] = ACTIONS(187),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(185),
    [anon_sym_tcp] = ACTIONS(187),
    [anon_sym_udp] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(185),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(187),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(185),
    [anon_sym_ssl] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(185),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(185),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(185),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(185),
    [anon_sym_sip] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(185),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(181),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(189),
    [anon_sym_xor] = ACTIONS(181),
    [anon_sym_CARET_CARET] = ACTIONS(181),
    [anon_sym_or] = ACTIONS(181),
    [anon_sym_PIPE_PIPE] = ACTIONS(181),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(181),
    [anon_sym_LPAREN] = ACTIONS(181),
    [anon_sym_RPAREN] = ACTIONS(181),
    [anon_sym_lookup_json_string] = ACTIONS(181),
    [anon_sym_lower] = ACTIONS(181),
    [anon_sym_regex_replace] = ACTIONS(181),
    [anon_sym_remove_bytes] = ACTIONS(181),
    [anon_sym_to_string] = ACTIONS(181),
    [anon_sym_upper] = ACTIONS(181),
    [anon_sym_url_decode] = ACTIONS(181),
    [anon_sym_uuidv4] = ACTIONS(181),
    [anon_sym_len] = ACTIONS(181),
    [anon_sym_ends_with] = ACTIONS(181),
    [anon_sym_starts_with] = ACTIONS(181),
    [anon_sym_any] = ACTIONS(181),
    [anon_sym_all] = ACTIONS(181),
    [anon_sym_true] = ACTIONS(181),
    [anon_sym_false] = ACTIONS(181),
    [anon_sym_not] = ACTIONS(181),
    [anon_sym_BANG] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(181),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(181),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(181),
    [anon_sym_icmp_DOTtype] = ACTIONS(181),
    [anon_sym_icmp_DOTcode] = ACTIONS(181),
    [anon_sym_ip_DOThdr_len] = ACTIONS(181),
    [anon_sym_ip_DOTlen] = ACTIONS(181),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(181),
    [anon_sym_ip_DOTttl] = ACTIONS(181),
    [anon_sym_tcp_DOTflags] = ACTIONS(183),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(181),
    [anon_sym_tcp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTsrcport] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc] = ACTIONS(183),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(181),
    [anon_sym_ip_DOTdst] = ACTIONS(183),
    [anon_sym_http_DOTcookie] = ACTIONS(181),
    [anon_sym_http_DOThost] = ACTIONS(181),
    [anon_sym_http_DOTreferer] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_http_DOTuser_agent] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(181),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(181),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(181),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(181),
    [anon_sym_icmp] = ACTIONS(183),
    [anon_sym_ip] = ACTIONS(183),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(181),
    [anon_sym_tcp] = ACTIONS(183),
    [anon_sym_udp] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(181),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(183),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(181),
    [anon_sym_ssl] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(181),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(181),
    [anon_sym_sip] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(181),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(191),
    [anon_sym_AMP_AMP] = ACTIONS(191),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(191),
    [anon_sym_CARET_CARET] = ACTIONS(191),
    [anon_sym_or] = ACTIONS(191),
    [anon_sym_PIPE_PIPE] = ACTIONS(191),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(191),
    [anon_sym_LPAREN] = ACTIONS(191),
    [anon_sym_RPAREN] = ACTIONS(191),
    [anon_sym_lookup_json_string] = ACTIONS(191),
    [anon_sym_lower] = ACTIONS(191),
    [anon_sym_regex_replace] = ACTIONS(191),
    [anon_sym_remove_bytes] = ACTIONS(191),
    [anon_sym_to_string] = ACTIONS(191),
    [anon_sym_upper] = ACTIONS(191),
    [anon_sym_url_decode] = ACTIONS(191),
    [anon_sym_uuidv4] = ACTIONS(191),
    [anon_sym_len] = ACTIONS(191),
    [anon_sym_ends_with] = ACTIONS(191),
    [anon_sym_starts_with] = ACTIONS(191),
    [anon_sym_any] = ACTIONS(191),
    [anon_sym_all] = ACTIONS(191),
    [anon_sym_true] = ACTIONS(191),
    [anon_sym_false] = ACTIONS(191),
    [anon_sym_not] = ACTIONS(191),
    [anon_sym_BANG] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(191),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(191),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(191),
    [anon_sym_icmp_DOTtype] = ACTIONS(191),
    [anon_sym_icmp_DOTcode] = ACTIONS(191),
    [anon_sym_ip_DOThdr_len] = ACTIONS(191),
    [anon_sym_ip_DOTlen] = ACTIONS(191),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(191),
    [anon_sym_ip_DOTttl] = ACTIONS(191),
    [anon_sym_tcp_DOTflags] = ACTIONS(193),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(191),
    [anon_sym_tcp_DOTdstport] = ACTIONS(191),
    [anon_sym_udp_DOTdstport] = ACTIONS(191),
    [anon_sym_udp_DOTsrcport] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(191),
    [anon_sym_ip_DOTsrc] = ACTIONS(193),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(191),
    [anon_sym_ip_DOTdst] = ACTIONS(193),
    [anon_sym_http_DOTcookie] = ACTIONS(191),
    [anon_sym_http_DOThost] = ACTIONS(191),
    [anon_sym_http_DOTreferer] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(191),
    [anon_sym_http_DOTuser_agent] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(191),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(191),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(191),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(191),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(191),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(191),
    [anon_sym_icmp] = ACTIONS(193),
    [anon_sym_ip] = ACTIONS(193),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(191),
    [anon_sym_tcp] = ACTIONS(193),
    [anon_sym_udp] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(191),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(191),
    [anon_sym_ssl] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(191),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(191),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(191),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(191),
    [anon_sym_sip] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(191),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(191),
  },
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(195),
    [anon_sym_AMP_AMP] = ACTIONS(195),
    [anon_sym_and] = ACTIONS(195),
    [anon_sym_xor] = ACTIONS(195),
    [anon_sym_CARET_CARET] = ACTIONS(195),
    [anon_sym_or] = ACTIONS(195),
    [anon_sym_PIPE_PIPE] = ACTIONS(195),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(195),
    [anon_sym_LPAREN] = ACTIONS(195),
    [anon_sym_RPAREN] = ACTIONS(195),
    [anon_sym_lookup_json_string] = ACTIONS(195),
    [anon_sym_lower] = ACTIONS(195),
    [anon_sym_regex_replace] = ACTIONS(195),
    [anon_sym_remove_bytes] = ACTIONS(195),
    [anon_sym_to_string] = ACTIONS(195),
    [anon_sym_upper] = ACTIONS(195),
    [anon_sym_url_decode] = ACTIONS(195),
    [anon_sym_uuidv4] = ACTIONS(195),
    [anon_sym_len] = ACTIONS(195),
    [anon_sym_ends_with] = ACTIONS(195),
    [anon_sym_starts_with] = ACTIONS(195),
    [anon_sym_any] = ACTIONS(195),
    [anon_sym_all] = ACTIONS(195),
    [anon_sym_true] = ACTIONS(195),
    [anon_sym_false] = ACTIONS(195),
    [anon_sym_not] = ACTIONS(195),
    [anon_sym_BANG] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(195),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(195),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(195),
    [anon_sym_icmp_DOTtype] = ACTIONS(195),
    [anon_sym_icmp_DOTcode] = ACTIONS(195),
    [anon_sym_ip_DOThdr_len] = ACTIONS(195),
    [anon_sym_ip_DOTlen] = ACTIONS(195),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(195),
    [anon_sym_ip_DOTttl] = ACTIONS(195),
    [anon_sym_tcp_DOTflags] = ACTIONS(197),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(195),
    [anon_sym_tcp_DOTdstport] = ACTIONS(195),
    [anon_sym_udp_DOTdstport] = ACTIONS(195),
    [anon_sym_udp_DOTsrcport] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(195),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(195),
    [anon_sym_ip_DOTdst] = ACTIONS(197),
    [anon_sym_http_DOTcookie] = ACTIONS(195),
    [anon_sym_http_DOThost] = ACTIONS(195),
    [anon_sym_http_DOTreferer] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(195),
    [anon_sym_http_DOTuser_agent] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(195),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(195),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(195),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(195),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(195),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(195),
    [anon_sym_icmp] = ACTIONS(197),
    [anon_sym_ip] = ACTIONS(197),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(195),
    [anon_sym_tcp] = ACTIONS(197),
    [anon_sym_udp] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(195),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(195),
    [anon_sym_ssl] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(195),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(195),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(195),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(195),
    [anon_sym_sip] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(195),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(195),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(199),
    [anon_sym_AMP_AMP] = ACTIONS(199),
    [anon_sym_and] = ACTIONS(199),
    [anon_sym_xor] = ACTIONS(199),
    [anon_sym_CARET_CARET] = ACTIONS(199),
    [anon_sym_or] = ACTIONS(199),
    [anon_sym_PIPE_PIPE] = ACTIONS(199),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(199),
    [anon_sym_LPAREN] = ACTIONS(199),
    [anon_sym_RPAREN] = ACTIONS(199),
    [anon_sym_lookup_json_string] = ACTIONS(199),
    [anon_sym_lower] = ACTIONS(199),
    [anon_sym_regex_replace] = ACTIONS(199),
    [anon_sym_remove_bytes] = ACTIONS(199),
    [anon_sym_to_string] = ACTIONS(199),
    [anon_sym_upper] = ACTIONS(199),
    [anon_sym_url_decode] = ACTIONS(199),
    [anon_sym_uuidv4] = ACTIONS(199),
    [anon_sym_len] = ACTIONS(199),
    [anon_sym_ends_with] = ACTIONS(199),
    [anon_sym_starts_with] = ACTIONS(199),
    [anon_sym_any] = ACTIONS(199),
    [anon_sym_all] = ACTIONS(199),
    [anon_sym_true] = ACTIONS(199),
    [anon_sym_false] = ACTIONS(199),
    [anon_sym_not] = ACTIONS(199),
    [anon_sym_BANG] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(199),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(199),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(199),
    [anon_sym_icmp_DOTtype] = ACTIONS(199),
    [anon_sym_icmp_DOTcode] = ACTIONS(199),
    [anon_sym_ip_DOThdr_len] = ACTIONS(199),
    [anon_sym_ip_DOTlen] = ACTIONS(199),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(199),
    [anon_sym_ip_DOTttl] = ACTIONS(199),
    [anon_sym_tcp_DOTflags] = ACTIONS(201),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(199),
    [anon_sym_tcp_DOTdstport] = ACTIONS(199),
    [anon_sym_udp_DOTdstport] = ACTIONS(199),
    [anon_sym_udp_DOTsrcport] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(199),
    [anon_sym_ip_DOTsrc] = ACTIONS(201),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(199),
    [anon_sym_ip_DOTdst] = ACTIONS(201),
    [anon_sym_http_DOTcookie] = ACTIONS(199),
    [anon_sym_http_DOThost] = ACTIONS(199),
    [anon_sym_http_DOTreferer] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(199),
    [anon_sym_http_DOTuser_agent] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(199),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(199),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(199),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(199),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(199),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(199),
    [anon_sym_icmp] = ACTIONS(201),
    [anon_sym_ip] = ACTIONS(201),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(199),
    [anon_sym_tcp] = ACTIONS(201),
    [anon_sym_udp] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(199),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(199),
    [anon_sym_ssl] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(199),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(199),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(199),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(199),
    [anon_sym_sip] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(199),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(199),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(203),
    [anon_sym_AMP_AMP] = ACTIONS(203),
    [anon_sym_and] = ACTIONS(203),
    [anon_sym_xor] = ACTIONS(203),
    [anon_sym_CARET_CARET] = ACTIONS(203),
    [anon_sym_or] = ACTIONS(203),
    [anon_sym_PIPE_PIPE] = ACTIONS(203),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(203),
    [anon_sym_LPAREN] = ACTIONS(203),
    [anon_sym_RPAREN] = ACTIONS(203),
    [anon_sym_lookup_json_string] = ACTIONS(203),
    [anon_sym_lower] = ACTIONS(203),
    [anon_sym_regex_replace] = ACTIONS(203),
    [anon_sym_remove_bytes] = ACTIONS(203),
    [anon_sym_to_string] = ACTIONS(203),
    [anon_sym_upper] = ACTIONS(203),
    [anon_sym_url_decode] = ACTIONS(203),
    [anon_sym_uuidv4] = ACTIONS(203),
    [anon_sym_len] = ACTIONS(203),
    [anon_sym_ends_with] = ACTIONS(203),
    [anon_sym_starts_with] = ACTIONS(203),
    [anon_sym_any] = ACTIONS(203),
    [anon_sym_all] = ACTIONS(203),
    [anon_sym_true] = ACTIONS(203),
    [anon_sym_false] = ACTIONS(203),
    [anon_sym_not] = ACTIONS(203),
    [anon_sym_BANG] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(203),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(203),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(203),
    [anon_sym_icmp_DOTtype] = ACTIONS(203),
    [anon_sym_icmp_DOTcode] = ACTIONS(203),
    [anon_sym_ip_DOThdr_len] = ACTIONS(203),
    [anon_sym_ip_DOTlen] = ACTIONS(203),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(203),
    [anon_sym_ip_DOTttl] = ACTIONS(203),
    [anon_sym_tcp_DOTflags] = ACTIONS(205),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(203),
    [anon_sym_tcp_DOTdstport] = ACTIONS(203),
    [anon_sym_udp_DOTdstport] = ACTIONS(203),
    [anon_sym_udp_DOTsrcport] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(203),
    [anon_sym_ip_DOTsrc] = ACTIONS(205),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(203),
    [anon_sym_ip_DOTdst] = ACTIONS(205),
    [anon_sym_http_DOTcookie] = ACTIONS(203),
    [anon_sym_http_DOThost] = ACTIONS(203),
    [anon_sym_http_DOTreferer] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(203),
    [anon_sym_http_DOTuser_agent] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(203),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(203),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(203),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(203),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(203),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(203),
    [anon_sym_icmp] = ACTIONS(205),
    [anon_sym_ip] = ACTIONS(205),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(203),
    [anon_sym_tcp] = ACTIONS(205),
    [anon_sym_udp] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(203),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(203),
    [anon_sym_ssl] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(203),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(203),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(203),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(203),
    [anon_sym_sip] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(203),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(203),
  },
  [28] = {
    [ts_builtin_sym_end] = ACTIONS(181),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(189),
    [anon_sym_xor] = ACTIONS(207),
    [anon_sym_CARET_CARET] = ACTIONS(207),
    [anon_sym_or] = ACTIONS(181),
    [anon_sym_PIPE_PIPE] = ACTIONS(181),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(181),
    [anon_sym_LPAREN] = ACTIONS(181),
    [anon_sym_RPAREN] = ACTIONS(181),
    [anon_sym_lookup_json_string] = ACTIONS(181),
    [anon_sym_lower] = ACTIONS(181),
    [anon_sym_regex_replace] = ACTIONS(181),
    [anon_sym_remove_bytes] = ACTIONS(181),
    [anon_sym_to_string] = ACTIONS(181),
    [anon_sym_upper] = ACTIONS(181),
    [anon_sym_url_decode] = ACTIONS(181),
    [anon_sym_uuidv4] = ACTIONS(181),
    [anon_sym_len] = ACTIONS(181),
    [anon_sym_ends_with] = ACTIONS(181),
    [anon_sym_starts_with] = ACTIONS(181),
    [anon_sym_any] = ACTIONS(181),
    [anon_sym_all] = ACTIONS(181),
    [anon_sym_true] = ACTIONS(181),
    [anon_sym_false] = ACTIONS(181),
    [anon_sym_not] = ACTIONS(181),
    [anon_sym_BANG] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(181),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(181),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(181),
    [anon_sym_icmp_DOTtype] = ACTIONS(181),
    [anon_sym_icmp_DOTcode] = ACTIONS(181),
    [anon_sym_ip_DOThdr_len] = ACTIONS(181),
    [anon_sym_ip_DOTlen] = ACTIONS(181),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(181),
    [anon_sym_ip_DOTttl] = ACTIONS(181),
    [anon_sym_tcp_DOTflags] = ACTIONS(183),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(181),
    [anon_sym_tcp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTsrcport] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc] = ACTIONS(183),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(181),
    [anon_sym_ip_DOTdst] = ACTIONS(183),
    [anon_sym_http_DOTcookie] = ACTIONS(181),
    [anon_sym_http_DOThost] = ACTIONS(181),
    [anon_sym_http_DOTreferer] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_http_DOTuser_agent] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(181),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(181),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(181),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(181),
    [anon_sym_icmp] = ACTIONS(183),
    [anon_sym_ip] = ACTIONS(183),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(181),
    [anon_sym_tcp] = ACTIONS(183),
    [anon_sym_udp] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(181),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(183),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(181),
    [anon_sym_ssl] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(181),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(181),
    [anon_sym_sip] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(181),
  },
  [29] = {
    [ts_builtin_sym_end] = ACTIONS(209),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(189),
    [anon_sym_xor] = ACTIONS(207),
    [anon_sym_CARET_CARET] = ACTIONS(207),
    [anon_sym_or] = ACTIONS(211),
    [anon_sym_PIPE_PIPE] = ACTIONS(211),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(209),
    [anon_sym_LPAREN] = ACTIONS(209),
    [anon_sym_lookup_json_string] = ACTIONS(209),
    [anon_sym_lower] = ACTIONS(209),
    [anon_sym_regex_replace] = ACTIONS(209),
    [anon_sym_remove_bytes] = ACTIONS(209),
    [anon_sym_to_string] = ACTIONS(209),
    [anon_sym_upper] = ACTIONS(209),
    [anon_sym_url_decode] = ACTIONS(209),
    [anon_sym_uuidv4] = ACTIONS(209),
    [anon_sym_len] = ACTIONS(209),
    [anon_sym_ends_with] = ACTIONS(209),
    [anon_sym_starts_with] = ACTIONS(209),
    [anon_sym_any] = ACTIONS(209),
    [anon_sym_all] = ACTIONS(209),
    [anon_sym_true] = ACTIONS(209),
    [anon_sym_false] = ACTIONS(209),
    [anon_sym_not] = ACTIONS(209),
    [anon_sym_BANG] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(209),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(209),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(209),
    [anon_sym_icmp_DOTtype] = ACTIONS(209),
    [anon_sym_icmp_DOTcode] = ACTIONS(209),
    [anon_sym_ip_DOThdr_len] = ACTIONS(209),
    [anon_sym_ip_DOTlen] = ACTIONS(209),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(209),
    [anon_sym_ip_DOTttl] = ACTIONS(209),
    [anon_sym_tcp_DOTflags] = ACTIONS(213),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(209),
    [anon_sym_tcp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTsrcport] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc] = ACTIONS(213),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(209),
    [anon_sym_ip_DOTdst] = ACTIONS(213),
    [anon_sym_http_DOTcookie] = ACTIONS(209),
    [anon_sym_http_DOThost] = ACTIONS(209),
    [anon_sym_http_DOTreferer] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(209),
    [anon_sym_http_DOTuser_agent] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(209),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(209),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(209),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(209),
    [anon_sym_icmp] = ACTIONS(213),
    [anon_sym_ip] = ACTIONS(213),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(209),
    [anon_sym_tcp] = ACTIONS(213),
    [anon_sym_udp] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(209),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(209),
    [anon_sym_ssl] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(209),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(209),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(209),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(209),
    [anon_sym_sip] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(209),
  },
  [30] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(215),
    [anon_sym_LPAREN] = ACTIONS(215),
    [anon_sym_lookup_json_string] = ACTIONS(215),
    [anon_sym_lower] = ACTIONS(215),
    [anon_sym_regex_replace] = ACTIONS(215),
    [anon_sym_remove_bytes] = ACTIONS(215),
    [anon_sym_to_string] = ACTIONS(215),
    [anon_sym_upper] = ACTIONS(215),
    [anon_sym_url_decode] = ACTIONS(215),
    [anon_sym_uuidv4] = ACTIONS(215),
    [anon_sym_len] = ACTIONS(215),
    [anon_sym_ends_with] = ACTIONS(215),
    [anon_sym_starts_with] = ACTIONS(215),
    [anon_sym_any] = ACTIONS(215),
    [anon_sym_all] = ACTIONS(215),
    [anon_sym_true] = ACTIONS(215),
    [anon_sym_false] = ACTIONS(215),
    [anon_sym_not] = ACTIONS(215),
    [anon_sym_BANG] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(215),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(215),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(215),
    [anon_sym_icmp_DOTtype] = ACTIONS(215),
    [anon_sym_icmp_DOTcode] = ACTIONS(215),
    [anon_sym_ip_DOThdr_len] = ACTIONS(215),
    [anon_sym_ip_DOTlen] = ACTIONS(215),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(215),
    [anon_sym_ip_DOTttl] = ACTIONS(215),
    [anon_sym_tcp_DOTflags] = ACTIONS(217),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(215),
    [anon_sym_tcp_DOTdstport] = ACTIONS(215),
    [anon_sym_udp_DOTdstport] = ACTIONS(215),
    [anon_sym_udp_DOTsrcport] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc] = ACTIONS(217),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(215),
    [anon_sym_ip_DOTdst] = ACTIONS(217),
    [anon_sym_http_DOTcookie] = ACTIONS(215),
    [anon_sym_http_DOThost] = ACTIONS(215),
    [anon_sym_http_DOTreferer] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(215),
    [anon_sym_http_DOTuser_agent] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(215),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(215),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(215),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(215),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(215),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(215),
    [anon_sym_icmp] = ACTIONS(217),
    [anon_sym_ip] = ACTIONS(217),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(215),
    [anon_sym_tcp] = ACTIONS(217),
    [anon_sym_udp] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(215),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(215),
    [anon_sym_ssl] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(215),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(215),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(215),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(215),
    [anon_sym_sip] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(215),
  },
  [31] = {
    [anon_sym_in] = ACTIONS(219),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(219),
    [anon_sym_ne] = ACTIONS(219),
    [anon_sym_lt] = ACTIONS(219),
    [anon_sym_le] = ACTIONS(219),
    [anon_sym_gt] = ACTIONS(219),
    [anon_sym_ge] = ACTIONS(219),
    [anon_sym_EQ_EQ] = ACTIONS(219),
    [anon_sym_BANG_EQ] = ACTIONS(219),
    [anon_sym_LT] = ACTIONS(221),
    [anon_sym_LT_EQ] = ACTIONS(219),
    [anon_sym_GT] = ACTIONS(221),
    [anon_sym_GT_EQ] = ACTIONS(219),
    [anon_sym_contains] = ACTIONS(219),
    [anon_sym_matches] = ACTIONS(219),
    [anon_sym_TILDE] = ACTIONS(219),
    [anon_sym_concat] = ACTIONS(219),
    [anon_sym_COMMA] = ACTIONS(219),
    [anon_sym_RPAREN] = ACTIONS(219),
    [anon_sym_lookup_json_string] = ACTIONS(219),
    [anon_sym_lower] = ACTIONS(219),
    [anon_sym_regex_replace] = ACTIONS(219),
    [anon_sym_remove_bytes] = ACTIONS(219),
    [anon_sym_to_string] = ACTIONS(219),
    [anon_sym_upper] = ACTIONS(219),
    [anon_sym_url_decode] = ACTIONS(219),
    [anon_sym_uuidv4] = ACTIONS(219),
    [sym_number] = ACTIONS(219),
    [sym_string] = ACTIONS(219),
    [anon_sym_http_DOTcookie] = ACTIONS(219),
    [anon_sym_http_DOThost] = ACTIONS(219),
    [anon_sym_http_DOTreferer] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(219),
    [anon_sym_http_DOTuser_agent] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(219),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(219),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(219),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(219),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(219),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(219),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(219),
    [anon_sym_icmp] = ACTIONS(219),
    [anon_sym_ip] = ACTIONS(221),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(219),
    [anon_sym_tcp] = ACTIONS(219),
    [anon_sym_udp] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(219),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(219),
  },
  [32] = {
    [anon_sym_in] = ACTIONS(223),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(223),
    [anon_sym_ne] = ACTIONS(223),
    [anon_sym_lt] = ACTIONS(223),
    [anon_sym_le] = ACTIONS(223),
    [anon_sym_gt] = ACTIONS(223),
    [anon_sym_ge] = ACTIONS(223),
    [anon_sym_EQ_EQ] = ACTIONS(223),
    [anon_sym_BANG_EQ] = ACTIONS(223),
    [anon_sym_LT] = ACTIONS(225),
    [anon_sym_LT_EQ] = ACTIONS(223),
    [anon_sym_GT] = ACTIONS(225),
    [anon_sym_GT_EQ] = ACTIONS(223),
    [anon_sym_contains] = ACTIONS(223),
    [anon_sym_matches] = ACTIONS(223),
    [anon_sym_TILDE] = ACTIONS(223),
    [anon_sym_concat] = ACTIONS(223),
    [anon_sym_COMMA] = ACTIONS(223),
    [anon_sym_RPAREN] = ACTIONS(223),
    [anon_sym_lookup_json_string] = ACTIONS(223),
    [anon_sym_lower] = ACTIONS(223),
    [anon_sym_regex_replace] = ACTIONS(223),
    [anon_sym_remove_bytes] = ACTIONS(223),
    [anon_sym_to_string] = ACTIONS(223),
    [anon_sym_upper] = ACTIONS(223),
    [anon_sym_url_decode] = ACTIONS(223),
    [anon_sym_uuidv4] = ACTIONS(223),
    [sym_number] = ACTIONS(223),
    [sym_string] = ACTIONS(223),
    [anon_sym_http_DOTcookie] = ACTIONS(223),
    [anon_sym_http_DOThost] = ACTIONS(223),
    [anon_sym_http_DOTreferer] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(223),
    [anon_sym_http_DOTuser_agent] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(223),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(223),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(223),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(223),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(223),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(223),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(223),
    [anon_sym_icmp] = ACTIONS(223),
    [anon_sym_ip] = ACTIONS(225),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(223),
    [anon_sym_tcp] = ACTIONS(223),
    [anon_sym_udp] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(223),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(223),
  },
  [33] = {
    [anon_sym_in] = ACTIONS(227),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(227),
    [anon_sym_ne] = ACTIONS(227),
    [anon_sym_lt] = ACTIONS(227),
    [anon_sym_le] = ACTIONS(227),
    [anon_sym_gt] = ACTIONS(227),
    [anon_sym_ge] = ACTIONS(227),
    [anon_sym_EQ_EQ] = ACTIONS(227),
    [anon_sym_BANG_EQ] = ACTIONS(227),
    [anon_sym_LT] = ACTIONS(229),
    [anon_sym_LT_EQ] = ACTIONS(227),
    [anon_sym_GT] = ACTIONS(229),
    [anon_sym_GT_EQ] = ACTIONS(227),
    [anon_sym_contains] = ACTIONS(227),
    [anon_sym_matches] = ACTIONS(227),
    [anon_sym_TILDE] = ACTIONS(227),
    [anon_sym_concat] = ACTIONS(227),
    [anon_sym_COMMA] = ACTIONS(227),
    [anon_sym_RPAREN] = ACTIONS(227),
    [anon_sym_lookup_json_string] = ACTIONS(227),
    [anon_sym_lower] = ACTIONS(227),
    [anon_sym_regex_replace] = ACTIONS(227),
    [anon_sym_remove_bytes] = ACTIONS(227),
    [anon_sym_to_string] = ACTIONS(227),
    [anon_sym_upper] = ACTIONS(227),
    [anon_sym_url_decode] = ACTIONS(227),
    [anon_sym_uuidv4] = ACTIONS(227),
    [sym_number] = ACTIONS(227),
    [sym_string] = ACTIONS(227),
    [anon_sym_http_DOTcookie] = ACTIONS(227),
    [anon_sym_http_DOThost] = ACTIONS(227),
    [anon_sym_http_DOTreferer] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(227),
    [anon_sym_http_DOTuser_agent] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(227),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(229),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(227),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(227),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(227),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(227),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(227),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(227),
    [anon_sym_icmp] = ACTIONS(227),
    [anon_sym_ip] = ACTIONS(229),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(227),
    [anon_sym_tcp] = ACTIONS(227),
    [anon_sym_udp] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(227),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(229),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(229),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(227),
  },
  [34] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(34),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(231),
    [anon_sym_RPAREN] = ACTIONS(234),
    [anon_sym_lookup_json_string] = ACTIONS(236),
    [anon_sym_lower] = ACTIONS(239),
    [anon_sym_regex_replace] = ACTIONS(242),
    [anon_sym_remove_bytes] = ACTIONS(245),
    [anon_sym_to_string] = ACTIONS(248),
    [anon_sym_upper] = ACTIONS(239),
    [anon_sym_url_decode] = ACTIONS(239),
    [anon_sym_uuidv4] = ACTIONS(251),
    [sym_string] = ACTIONS(254),
    [anon_sym_http_DOTcookie] = ACTIONS(257),
    [anon_sym_http_DOThost] = ACTIONS(257),
    [anon_sym_http_DOTreferer] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(260),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(257),
    [anon_sym_http_DOTuser_agent] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(257),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(257),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(257),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(257),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(257),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(257),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(257),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(260),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(257),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(257),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(257),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(257),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(257),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(257),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(257),
    [anon_sym_icmp] = ACTIONS(257),
    [anon_sym_ip] = ACTIONS(260),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(257),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(257),
    [anon_sym_tcp] = ACTIONS(257),
    [anon_sym_udp] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(257),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(257),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(263),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(266),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(266),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(266),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(266),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(266),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(269),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(269),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(269),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(269),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(269),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(269),
  },
  [35] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(34),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_RPAREN] = ACTIONS(274),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [36] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(34),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_RPAREN] = ACTIONS(290),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [37] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(34),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_RPAREN] = ACTIONS(292),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [38] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(210),
    [sym_stringlike_field] = STATE(209),
    [sym_string_field] = STATE(31),
    [sym_bytes_field] = STATE(209),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(308),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [39] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(204),
    [sym_stringlike_field] = STATE(203),
    [sym_string_field] = STATE(31),
    [sym_bytes_field] = STATE(203),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(308),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [40] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(37),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [41] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(35),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [42] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(139),
    [sym_stringlike_field] = STATE(142),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [sym_string] = ACTIONS(312),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [43] = {
    [sym_string_array] = STATE(183),
    [sym_stringlike_field] = STATE(49),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(182),
    [sym_array_string_field] = STATE(181),
    [aux_sym_string_func_repeat1] = STATE(36),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(272),
    [anon_sym_lookup_json_string] = ACTIONS(276),
    [anon_sym_lower] = ACTIONS(278),
    [anon_sym_regex_replace] = ACTIONS(280),
    [anon_sym_remove_bytes] = ACTIONS(282),
    [anon_sym_to_string] = ACTIONS(284),
    [anon_sym_upper] = ACTIONS(278),
    [anon_sym_url_decode] = ACTIONS(278),
    [anon_sym_uuidv4] = ACTIONS(286),
    [sym_string] = ACTIONS(288),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [44] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(202),
    [sym_stringlike_field] = STATE(201),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [45] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(206),
    [sym_stringlike_field] = STATE(205),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [46] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(101),
    [sym_stringlike_field] = STATE(98),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [47] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(169),
    [sym_stringlike_field] = STATE(229),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [48] = {
    [sym_string_array] = STATE(130),
    [sym__string_array_expansion] = STATE(212),
    [sym_stringlike_field] = STATE(211),
    [sym_string_field] = STATE(31),
    [sym_map_string_array_field] = STATE(138),
    [sym_array_string_field] = STATE(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(294),
    [anon_sym_lookup_json_string] = ACTIONS(296),
    [anon_sym_lower] = ACTIONS(298),
    [anon_sym_regex_replace] = ACTIONS(300),
    [anon_sym_remove_bytes] = ACTIONS(302),
    [anon_sym_to_string] = ACTIONS(304),
    [anon_sym_upper] = ACTIONS(298),
    [anon_sym_url_decode] = ACTIONS(298),
    [anon_sym_uuidv4] = ACTIONS(306),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(310),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(310),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(310),
  },
  [49] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(314),
    [anon_sym_COMMA] = ACTIONS(316),
    [anon_sym_RPAREN] = ACTIONS(314),
    [anon_sym_lookup_json_string] = ACTIONS(314),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(314),
    [anon_sym_remove_bytes] = ACTIONS(314),
    [anon_sym_to_string] = ACTIONS(314),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(314),
    [sym_string] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(314),
    [anon_sym_http_DOThost] = ACTIONS(314),
    [anon_sym_http_DOTreferer] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(314),
    [anon_sym_http_DOTuser_agent] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(314),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(314),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(314),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(314),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(314),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(314),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(314),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(314),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(314),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(314),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(314),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(314),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(314),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(314),
    [anon_sym_icmp] = ACTIONS(314),
    [anon_sym_ip] = ACTIONS(318),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(314),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(314),
    [anon_sym_tcp] = ACTIONS(314),
    [anon_sym_udp] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(314),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(314),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(314),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(314),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(314),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(314),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(314),
  },
  [50] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(234),
    [anon_sym_RPAREN] = ACTIONS(234),
    [anon_sym_lookup_json_string] = ACTIONS(234),
    [anon_sym_lower] = ACTIONS(234),
    [anon_sym_regex_replace] = ACTIONS(234),
    [anon_sym_remove_bytes] = ACTIONS(234),
    [anon_sym_to_string] = ACTIONS(234),
    [anon_sym_upper] = ACTIONS(234),
    [anon_sym_url_decode] = ACTIONS(234),
    [anon_sym_uuidv4] = ACTIONS(234),
    [sym_string] = ACTIONS(234),
    [anon_sym_http_DOTcookie] = ACTIONS(234),
    [anon_sym_http_DOThost] = ACTIONS(234),
    [anon_sym_http_DOTreferer] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(320),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(234),
    [anon_sym_http_DOTuser_agent] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(234),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(234),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(234),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(234),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(234),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(234),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(234),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(320),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(234),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(234),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(234),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(234),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(234),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(234),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(234),
    [anon_sym_icmp] = ACTIONS(234),
    [anon_sym_ip] = ACTIONS(320),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(234),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(234),
    [anon_sym_tcp] = ACTIONS(234),
    [anon_sym_udp] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(234),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(320),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(320),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(320),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(320),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(320),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(234),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(234),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(234),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(234),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(234),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(234),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(322), 1,
      anon_sym_len,
    ACTIONS(326), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(19), 1,
      sym_bool_field,
    STATE(75), 1,
      sym_number_field,
    STATE(106), 1,
      sym_array_number_field,
    STATE(109), 1,
      sym_number_array,
    STATE(110), 1,
      sym_bool_array,
    ACTIONS(35), 2,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_tcp_DOTflags,
    ACTIONS(324), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    ACTIONS(39), 3,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
      anon_sym_ip_DOTdst,
    STATE(229), 3,
      sym_boollike_field,
      sym_numberlike_field,
      sym_ip_field,
    ACTIONS(53), 18,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_sip,
      anon_sym_tcp_DOTflags_DOTack,
      anon_sym_tcp_DOTflags_DOTcwr,
      anon_sym_tcp_DOTflags_DOTecn,
      anon_sym_tcp_DOTflags_DOTfin,
      anon_sym_tcp_DOTflags_DOTpush,
      anon_sym_tcp_DOTflags_DOTreset,
      anon_sym_tcp_DOTflags_DOTsyn,
      anon_sym_tcp_DOTflags_DOTurg,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
      anon_sym_http_DOTrequest_DOTbody_DOTtruncated,
    ACTIONS(33), 22,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
      anon_sym_icmp_DOTtype,
      anon_sym_icmp_DOTcode,
      anon_sym_ip_DOThdr_len,
      anon_sym_ip_DOTlen,
      anon_sym_ip_DOTopt_DOTtype,
      anon_sym_ip_DOTttl,
      anon_sym_tcp_DOTsrcport,
      anon_sym_tcp_DOTdstport,
      anon_sym_udp_DOTdstport,
      anon_sym_udp_DOTsrcport,
      anon_sym_http_DOTrequest_DOTbody_DOTsize,
      anon_sym_http_DOTresponse_DOTcode,
      anon_sym_http_DOTresponse_DOT1xxx_code,
  [87] = 20,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    ACTIONS(322), 1,
      anon_sym_len,
    ACTIONS(326), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(106), 1,
      sym_array_number_field,
    STATE(114), 1,
      sym_array_string_field,
    STATE(179), 1,
      sym_string_array,
    STATE(199), 1,
      sym_bool_array,
    STATE(200), 1,
      sym_number_array,
    STATE(236), 1,
      sym_map_string_array_field,
    ACTIONS(324), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [165] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(239), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [227] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(240), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [289] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(214), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [351] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(99), 1,
      sym__string_array_expansion,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [413] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(169), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [475] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(206), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [537] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(213), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [599] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(101), 1,
      sym__string_array_expansion,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [661] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(212), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [723] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(248), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [785] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(139), 1,
      sym__string_array_expansion,
    STATE(154), 1,
      sym_string_array,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [847] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(210), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [909] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(241), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [971] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(294), 1,
      anon_sym_concat,
    ACTIONS(296), 1,
      anon_sym_lookup_json_string,
    ACTIONS(300), 1,
      anon_sym_regex_replace,
    ACTIONS(302), 1,
      anon_sym_remove_bytes,
    ACTIONS(304), 1,
      anon_sym_to_string,
    ACTIONS(306), 1,
      anon_sym_uuidv4,
    STATE(114), 1,
      sym_array_string_field,
    STATE(138), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_string_array,
    STATE(215), 1,
      sym__string_array_expansion,
    ACTIONS(298), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(310), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [1033] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(328), 1,
      anon_sym_in,
    ACTIONS(332), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(330), 13,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1059] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(336), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(334), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1083] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(338), 1,
      anon_sym_in,
    ACTIONS(342), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(340), 13,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1109] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(346), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(344), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1133] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(348), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1157] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(352), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1181] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(358), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(356), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1205] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(362), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(360), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1229] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(366), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(364), 12,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_RPAREN,
  [1251] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(370), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(368), 12,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_RPAREN,
  [1273] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(374), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(372), 12,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_RPAREN,
  [1295] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(376), 1,
      anon_sym_in,
    ACTIONS(380), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(378), 10,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1318] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(382), 1,
      anon_sym_in,
    ACTIONS(386), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(384), 10,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1341] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(390), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(388), 11,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1362] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(322), 1,
      anon_sym_len,
    ACTIONS(326), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(106), 1,
      sym_array_number_field,
    ACTIONS(324), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(155), 2,
      sym_number_array,
      sym_bool_array,
  [1383] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(322), 1,
      anon_sym_len,
    ACTIONS(326), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(106), 1,
      sym_array_number_field,
    ACTIONS(324), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(221), 2,
      sym_number_array,
      sym_bool_array,
  [1404] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(392), 1,
      anon_sym_RPAREN,
    ACTIONS(189), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(207), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(211), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [1423] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(394), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [1435] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(396), 1,
      anon_sym_RBRACE,
    ACTIONS(398), 1,
      sym_ipv4,
    STATE(85), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1450] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(401), 1,
      anon_sym_in,
    ACTIONS(403), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [1463] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(405), 1,
      anon_sym_RBRACE,
    ACTIONS(407), 1,
      sym_ipv4,
    STATE(85), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1478] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      anon_sym_RPAREN,
    STATE(88), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(411), 2,
      sym_number,
      sym_string,
  [1492] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(414), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1502] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(416), 1,
      anon_sym_RPAREN,
    STATE(88), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1516] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(420), 1,
      anon_sym_COMMA,
    ACTIONS(422), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1528] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(407), 1,
      sym_ipv4,
    STATE(87), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1540] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(424), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1550] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(426), 1,
      anon_sym_RPAREN,
    STATE(88), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1564] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(428), 1,
      anon_sym_RPAREN,
    STATE(88), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1578] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(407), 1,
      sym_ipv4,
    STATE(24), 2,
      sym__ip,
      sym_ip_range,
  [1589] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(430), 1,
      anon_sym_RBRACE,
    ACTIONS(432), 1,
      sym_string,
    STATE(105), 1,
      aux_sym_string_set_repeat1,
  [1602] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(90), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1613] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(95), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1624] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(434), 1,
      anon_sym_RBRACE,
    ACTIONS(436), 1,
      sym_number,
    STATE(104), 1,
      aux_sym_number_set_repeat1,
  [1637] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(94), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [1648] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1657] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(438), 1,
      anon_sym_LBRACE,
    ACTIONS(440), 1,
      sym_ip_list,
    STATE(12), 1,
      sym_ip_set,
  [1670] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(442), 1,
      anon_sym_RBRACE,
    ACTIONS(444), 1,
      sym_number,
    STATE(104), 1,
      aux_sym_number_set_repeat1,
  [1683] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(447), 1,
      anon_sym_RBRACE,
    ACTIONS(449), 1,
      sym_string,
    STATE(105), 1,
      aux_sym_string_set_repeat1,
  [1696] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(454), 1,
      anon_sym_LBRACK,
  [1706] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      sym_number,
    STATE(100), 1,
      aux_sym_number_set_repeat1,
  [1716] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(458), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(460), 1,
      anon_sym_LBRACK,
  [1726] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(464), 1,
      anon_sym_LBRACK,
  [1736] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(466), 1,
      anon_sym_LBRACK,
  [1746] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(470), 1,
      anon_sym_LBRACK,
  [1756] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(472), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(474), 1,
      anon_sym_LBRACK,
  [1766] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(476), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(478), 1,
      anon_sym_LBRACK,
  [1776] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(482), 1,
      anon_sym_LBRACK,
  [1786] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(486), 1,
      anon_sym_LBRACK,
  [1796] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(490), 1,
      anon_sym_LBRACK,
  [1806] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_LBRACE,
    STATE(12), 1,
      sym_number_set,
  [1816] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(496), 1,
      anon_sym_LBRACK,
  [1826] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(500), 1,
      anon_sym_LBRACK,
  [1836] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      sym_string,
    STATE(97), 1,
      aux_sym_string_set_repeat1,
  [1846] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(504), 1,
      anon_sym_LBRACE,
    STATE(12), 1,
      sym_string_set,
  [1856] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(508), 1,
      anon_sym_LBRACK,
  [1866] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(504), 1,
      anon_sym_LBRACE,
    STATE(192), 1,
      sym_string_set,
  [1876] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_LBRACE,
    STATE(192), 1,
      sym_number_set,
  [1886] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      sym_string,
    ACTIONS(512), 1,
      anon_sym_STAR,
  [1896] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(516), 1,
      anon_sym_LBRACK,
  [1906] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [1914] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(522), 1,
      anon_sym_LBRACK,
  [1924] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(526), 1,
      anon_sym_LBRACK,
  [1934] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(530), 1,
      anon_sym_LBRACK,
  [1944] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_RPAREN,
  [1951] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK,
  [1958] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_LPAREN,
  [1965] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(536), 1,
      sym_string,
  [1972] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      sym_string,
  [1979] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(540), 1,
      sym_string,
  [1986] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      sym_string,
  [1993] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(544), 1,
      anon_sym_LBRACK,
  [2000] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      anon_sym_COMMA,
  [2007] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(472), 1,
      anon_sym_LBRACK,
  [2014] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      anon_sym_LBRACK,
  [2021] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      anon_sym_COMMA,
  [2028] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(550), 1,
      sym_string,
  [2035] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      sym_string,
  [2042] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      anon_sym_LPAREN,
  [2049] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(556), 1,
      anon_sym_RPAREN,
  [2056] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_LPAREN,
  [2063] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(560), 1,
      anon_sym_LPAREN,
  [2070] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_LPAREN,
  [2077] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(564), 1,
      anon_sym_LPAREN,
  [2084] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LPAREN,
  [2091] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(568), 1,
      aux_sym_ip_range_token1,
  [2098] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(458), 1,
      anon_sym_LBRACK,
  [2105] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2112] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2119] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(572), 1,
      anon_sym_LPAREN,
  [2126] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      sym_string,
  [2133] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      anon_sym_RBRACK,
  [2140] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_LBRACK,
  [2147] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      sym_number,
  [2154] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(580), 1,
      sym_number,
  [2161] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_COMMA,
  [2168] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(584), 1,
      anon_sym_COMMA,
  [2175] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_RPAREN,
  [2182] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(588), 1,
      anon_sym_RPAREN,
  [2189] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACK,
  [2196] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_RPAREN,
  [2203] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      anon_sym_RPAREN,
  [2210] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_RPAREN,
  [2217] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      sym_number,
  [2224] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      sym_number,
  [2231] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(600), 1,
      anon_sym_RBRACK,
  [2238] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      sym_string,
  [2245] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      sym_string,
  [2252] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(604), 1,
      anon_sym_RBRACK,
  [2259] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_RBRACK,
  [2266] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(608), 1,
      anon_sym_RBRACK,
  [2273] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      sym_number,
  [2280] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(610), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2287] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 1,
      anon_sym_LBRACK,
  [2294] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_LBRACK,
  [2301] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_LBRACK,
  [2308] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(614), 1,
      anon_sym_LBRACK,
  [2315] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LBRACK,
  [2322] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2329] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      sym_string,
  [2336] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(620), 1,
      sym_string,
  [2343] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      anon_sym_LBRACK,
  [2350] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      anon_sym_LBRACK,
  [2357] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(476), 1,
      anon_sym_LBRACK,
  [2364] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(624), 1,
      anon_sym_LBRACK,
  [2371] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(626), 1,
      anon_sym_RPAREN,
  [2378] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(628), 1,
      ts_builtin_sym_end,
  [2385] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(630), 1,
      anon_sym_RPAREN,
  [2392] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(632), 1,
      anon_sym_RPAREN,
  [2399] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      anon_sym_LBRACK,
  [2406] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_LBRACK,
  [2413] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK,
  [2420] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(634), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2427] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(636), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2434] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(638), 1,
      anon_sym_COMMA,
  [2441] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(640), 1,
      anon_sym_COMMA,
  [2448] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(642), 1,
      anon_sym_RPAREN,
  [2455] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(644), 1,
      anon_sym_RPAREN,
  [2462] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(646), 1,
      anon_sym_RPAREN,
  [2469] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      anon_sym_RPAREN,
  [2476] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(650), 1,
      anon_sym_LPAREN,
  [2483] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(652), 1,
      anon_sym_LPAREN,
  [2490] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(654), 1,
      anon_sym_COMMA,
  [2497] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(656), 1,
      anon_sym_COMMA,
  [2504] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(658), 1,
      anon_sym_COMMA,
  [2511] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(660), 1,
      anon_sym_COMMA,
  [2518] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(662), 1,
      anon_sym_RPAREN,
  [2525] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(664), 1,
      anon_sym_RPAREN,
  [2532] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(666), 1,
      anon_sym_RPAREN,
  [2539] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(668), 1,
      anon_sym_RBRACK,
  [2546] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(670), 1,
      anon_sym_LBRACK,
  [2553] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(672), 1,
      anon_sym_LPAREN,
  [2560] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(674), 1,
      anon_sym_LPAREN,
  [2567] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(676), 1,
      anon_sym_RPAREN,
  [2574] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2581] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(678), 1,
      anon_sym_LPAREN,
  [2588] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(680), 1,
      anon_sym_RPAREN,
  [2595] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(682), 1,
      anon_sym_RPAREN,
  [2602] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(684), 1,
      anon_sym_RPAREN,
  [2609] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      sym_string,
  [2616] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(686), 1,
      anon_sym_LPAREN,
  [2623] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(688), 1,
      anon_sym_LPAREN,
  [2630] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(690), 1,
      anon_sym_RPAREN,
  [2637] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(692), 1,
      anon_sym_LPAREN,
  [2644] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(694), 1,
      anon_sym_LPAREN,
  [2651] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(696), 1,
      anon_sym_LPAREN,
  [2658] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(698), 1,
      sym_string,
  [2665] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(700), 1,
      sym_string,
  [2672] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(702), 1,
      sym_string,
  [2679] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(704), 1,
      anon_sym_LBRACK,
  [2686] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(706), 1,
      anon_sym_LPAREN,
  [2693] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(708), 1,
      anon_sym_LPAREN,
  [2700] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(710), 1,
      anon_sym_COMMA,
  [2707] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(712), 1,
      anon_sym_COMMA,
  [2714] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(714), 1,
      anon_sym_COMMA,
  [2721] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(716), 1,
      anon_sym_LPAREN,
  [2728] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(718), 1,
      anon_sym_LPAREN,
  [2735] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(720), 1,
      anon_sym_COMMA,
  [2742] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(722), 1,
      anon_sym_LPAREN,
  [2749] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(724), 1,
      anon_sym_LPAREN,
  [2756] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(726), 1,
      sym_string,
  [2763] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(728), 1,
      anon_sym_COMMA,
  [2770] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(730), 1,
      anon_sym_LPAREN,
  [2777] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(732), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(51)] = 0,
  [SMALL_STATE(52)] = 87,
  [SMALL_STATE(53)] = 165,
  [SMALL_STATE(54)] = 227,
  [SMALL_STATE(55)] = 289,
  [SMALL_STATE(56)] = 351,
  [SMALL_STATE(57)] = 413,
  [SMALL_STATE(58)] = 475,
  [SMALL_STATE(59)] = 537,
  [SMALL_STATE(60)] = 599,
  [SMALL_STATE(61)] = 661,
  [SMALL_STATE(62)] = 723,
  [SMALL_STATE(63)] = 785,
  [SMALL_STATE(64)] = 847,
  [SMALL_STATE(65)] = 909,
  [SMALL_STATE(66)] = 971,
  [SMALL_STATE(67)] = 1033,
  [SMALL_STATE(68)] = 1059,
  [SMALL_STATE(69)] = 1083,
  [SMALL_STATE(70)] = 1109,
  [SMALL_STATE(71)] = 1133,
  [SMALL_STATE(72)] = 1157,
  [SMALL_STATE(73)] = 1181,
  [SMALL_STATE(74)] = 1205,
  [SMALL_STATE(75)] = 1229,
  [SMALL_STATE(76)] = 1251,
  [SMALL_STATE(77)] = 1273,
  [SMALL_STATE(78)] = 1295,
  [SMALL_STATE(79)] = 1318,
  [SMALL_STATE(80)] = 1341,
  [SMALL_STATE(81)] = 1362,
  [SMALL_STATE(82)] = 1383,
  [SMALL_STATE(83)] = 1404,
  [SMALL_STATE(84)] = 1423,
  [SMALL_STATE(85)] = 1435,
  [SMALL_STATE(86)] = 1450,
  [SMALL_STATE(87)] = 1463,
  [SMALL_STATE(88)] = 1478,
  [SMALL_STATE(89)] = 1492,
  [SMALL_STATE(90)] = 1502,
  [SMALL_STATE(91)] = 1516,
  [SMALL_STATE(92)] = 1528,
  [SMALL_STATE(93)] = 1540,
  [SMALL_STATE(94)] = 1550,
  [SMALL_STATE(95)] = 1564,
  [SMALL_STATE(96)] = 1578,
  [SMALL_STATE(97)] = 1589,
  [SMALL_STATE(98)] = 1602,
  [SMALL_STATE(99)] = 1613,
  [SMALL_STATE(100)] = 1624,
  [SMALL_STATE(101)] = 1637,
  [SMALL_STATE(102)] = 1648,
  [SMALL_STATE(103)] = 1657,
  [SMALL_STATE(104)] = 1670,
  [SMALL_STATE(105)] = 1683,
  [SMALL_STATE(106)] = 1696,
  [SMALL_STATE(107)] = 1706,
  [SMALL_STATE(108)] = 1716,
  [SMALL_STATE(109)] = 1726,
  [SMALL_STATE(110)] = 1736,
  [SMALL_STATE(111)] = 1746,
  [SMALL_STATE(112)] = 1756,
  [SMALL_STATE(113)] = 1766,
  [SMALL_STATE(114)] = 1776,
  [SMALL_STATE(115)] = 1786,
  [SMALL_STATE(116)] = 1796,
  [SMALL_STATE(117)] = 1806,
  [SMALL_STATE(118)] = 1816,
  [SMALL_STATE(119)] = 1826,
  [SMALL_STATE(120)] = 1836,
  [SMALL_STATE(121)] = 1846,
  [SMALL_STATE(122)] = 1856,
  [SMALL_STATE(123)] = 1866,
  [SMALL_STATE(124)] = 1876,
  [SMALL_STATE(125)] = 1886,
  [SMALL_STATE(126)] = 1896,
  [SMALL_STATE(127)] = 1906,
  [SMALL_STATE(128)] = 1914,
  [SMALL_STATE(129)] = 1924,
  [SMALL_STATE(130)] = 1934,
  [SMALL_STATE(131)] = 1944,
  [SMALL_STATE(132)] = 1951,
  [SMALL_STATE(133)] = 1958,
  [SMALL_STATE(134)] = 1965,
  [SMALL_STATE(135)] = 1972,
  [SMALL_STATE(136)] = 1979,
  [SMALL_STATE(137)] = 1986,
  [SMALL_STATE(138)] = 1993,
  [SMALL_STATE(139)] = 2000,
  [SMALL_STATE(140)] = 2007,
  [SMALL_STATE(141)] = 2014,
  [SMALL_STATE(142)] = 2021,
  [SMALL_STATE(143)] = 2028,
  [SMALL_STATE(144)] = 2035,
  [SMALL_STATE(145)] = 2042,
  [SMALL_STATE(146)] = 2049,
  [SMALL_STATE(147)] = 2056,
  [SMALL_STATE(148)] = 2063,
  [SMALL_STATE(149)] = 2070,
  [SMALL_STATE(150)] = 2077,
  [SMALL_STATE(151)] = 2084,
  [SMALL_STATE(152)] = 2091,
  [SMALL_STATE(153)] = 2098,
  [SMALL_STATE(154)] = 2105,
  [SMALL_STATE(155)] = 2112,
  [SMALL_STATE(156)] = 2119,
  [SMALL_STATE(157)] = 2126,
  [SMALL_STATE(158)] = 2133,
  [SMALL_STATE(159)] = 2140,
  [SMALL_STATE(160)] = 2147,
  [SMALL_STATE(161)] = 2154,
  [SMALL_STATE(162)] = 2161,
  [SMALL_STATE(163)] = 2168,
  [SMALL_STATE(164)] = 2175,
  [SMALL_STATE(165)] = 2182,
  [SMALL_STATE(166)] = 2189,
  [SMALL_STATE(167)] = 2196,
  [SMALL_STATE(168)] = 2203,
  [SMALL_STATE(169)] = 2210,
  [SMALL_STATE(170)] = 2217,
  [SMALL_STATE(171)] = 2224,
  [SMALL_STATE(172)] = 2231,
  [SMALL_STATE(173)] = 2238,
  [SMALL_STATE(174)] = 2245,
  [SMALL_STATE(175)] = 2252,
  [SMALL_STATE(176)] = 2259,
  [SMALL_STATE(177)] = 2266,
  [SMALL_STATE(178)] = 2273,
  [SMALL_STATE(179)] = 2280,
  [SMALL_STATE(180)] = 2287,
  [SMALL_STATE(181)] = 2294,
  [SMALL_STATE(182)] = 2301,
  [SMALL_STATE(183)] = 2308,
  [SMALL_STATE(184)] = 2315,
  [SMALL_STATE(185)] = 2322,
  [SMALL_STATE(186)] = 2329,
  [SMALL_STATE(187)] = 2336,
  [SMALL_STATE(188)] = 2343,
  [SMALL_STATE(189)] = 2350,
  [SMALL_STATE(190)] = 2357,
  [SMALL_STATE(191)] = 2364,
  [SMALL_STATE(192)] = 2371,
  [SMALL_STATE(193)] = 2378,
  [SMALL_STATE(194)] = 2385,
  [SMALL_STATE(195)] = 2392,
  [SMALL_STATE(196)] = 2399,
  [SMALL_STATE(197)] = 2406,
  [SMALL_STATE(198)] = 2413,
  [SMALL_STATE(199)] = 2420,
  [SMALL_STATE(200)] = 2427,
  [SMALL_STATE(201)] = 2434,
  [SMALL_STATE(202)] = 2441,
  [SMALL_STATE(203)] = 2448,
  [SMALL_STATE(204)] = 2455,
  [SMALL_STATE(205)] = 2462,
  [SMALL_STATE(206)] = 2469,
  [SMALL_STATE(207)] = 2476,
  [SMALL_STATE(208)] = 2483,
  [SMALL_STATE(209)] = 2490,
  [SMALL_STATE(210)] = 2497,
  [SMALL_STATE(211)] = 2504,
  [SMALL_STATE(212)] = 2511,
  [SMALL_STATE(213)] = 2518,
  [SMALL_STATE(214)] = 2525,
  [SMALL_STATE(215)] = 2532,
  [SMALL_STATE(216)] = 2539,
  [SMALL_STATE(217)] = 2546,
  [SMALL_STATE(218)] = 2553,
  [SMALL_STATE(219)] = 2560,
  [SMALL_STATE(220)] = 2567,
  [SMALL_STATE(221)] = 2574,
  [SMALL_STATE(222)] = 2581,
  [SMALL_STATE(223)] = 2588,
  [SMALL_STATE(224)] = 2595,
  [SMALL_STATE(225)] = 2602,
  [SMALL_STATE(226)] = 2609,
  [SMALL_STATE(227)] = 2616,
  [SMALL_STATE(228)] = 2623,
  [SMALL_STATE(229)] = 2630,
  [SMALL_STATE(230)] = 2637,
  [SMALL_STATE(231)] = 2644,
  [SMALL_STATE(232)] = 2651,
  [SMALL_STATE(233)] = 2658,
  [SMALL_STATE(234)] = 2665,
  [SMALL_STATE(235)] = 2672,
  [SMALL_STATE(236)] = 2679,
  [SMALL_STATE(237)] = 2686,
  [SMALL_STATE(238)] = 2693,
  [SMALL_STATE(239)] = 2700,
  [SMALL_STATE(240)] = 2707,
  [SMALL_STATE(241)] = 2714,
  [SMALL_STATE(242)] = 2721,
  [SMALL_STATE(243)] = 2728,
  [SMALL_STATE(244)] = 2735,
  [SMALL_STATE(245)] = 2742,
  [SMALL_STATE(246)] = 2749,
  [SMALL_STATE(247)] = 2756,
  [SMALL_STATE(248)] = 2763,
  [SMALL_STATE(249)] = 2770,
  [SMALL_STATE(250)] = 2777,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(133),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(249),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(243),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(242),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(232),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(231),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(230),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(222),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(219),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(218),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(77),
  [37] = {.entry = {.count = 1, .reusable = false}}, SHIFT(84),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [43] = {.entry = {.count = 1, .reusable = false}}, SHIFT(32),
  [45] = {.entry = {.count = 1, .reusable = true}}, SHIFT(217),
  [47] = {.entry = {.count = 1, .reusable = false}}, SHIFT(217),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(198),
  [51] = {.entry = {.count = 1, .reusable = true}}, SHIFT(196),
  [53] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [57] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(133),
  [60] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(6),
  [63] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(249),
  [66] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(243),
  [69] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(242),
  [72] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(232),
  [75] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(231),
  [78] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(230),
  [81] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(222),
  [84] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(219),
  [87] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(218),
  [90] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(15),
  [93] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(30),
  [96] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(77),
  [99] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(77),
  [102] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(84),
  [105] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(84),
  [108] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(32),
  [111] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(32),
  [114] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(217),
  [117] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(217),
  [120] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(198),
  [123] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(196),
  [126] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(22),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [133] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [135] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [137] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [139] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [141] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 6, .production_id = 18),
  [143] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 6, .production_id = 18),
  [145] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [147] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [149] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [151] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [153] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 5, .production_id = 12),
  [155] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 5, .production_id = 12),
  [157] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [159] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [161] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 1),
  [163] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 1),
  [165] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [167] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [169] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [171] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [173] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boollike_field, 1),
  [175] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boollike_field, 1),
  [177] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 7, .production_id = 19),
  [179] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 7, .production_id = 19),
  [181] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 2),
  [183] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 2),
  [185] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [187] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [191] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [193] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [195] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [197] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [199] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [201] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [203] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boollike_field, 4, .production_id = 7),
  [205] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boollike_field, 4, .production_id = 7),
  [207] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [209] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [211] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [213] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [215] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [217] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [219] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stringlike_field, 1),
  [221] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stringlike_field, 1),
  [223] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [225] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [227] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stringlike_field, 4, .production_id = 7),
  [229] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stringlike_field, 4, .production_id = 7),
  [231] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(245),
  [234] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [236] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(237),
  [239] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(227),
  [242] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(250),
  [245] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(246),
  [248] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(238),
  [251] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(228),
  [254] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(49),
  [257] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(32),
  [260] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(32),
  [263] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(217),
  [266] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(217),
  [269] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(198),
  [272] = {.entry = {.count = 1, .reusable = true}}, SHIFT(245),
  [274] = {.entry = {.count = 1, .reusable = true}}, SHIFT(184),
  [276] = {.entry = {.count = 1, .reusable = true}}, SHIFT(237),
  [278] = {.entry = {.count = 1, .reusable = true}}, SHIFT(227),
  [280] = {.entry = {.count = 1, .reusable = true}}, SHIFT(250),
  [282] = {.entry = {.count = 1, .reusable = true}}, SHIFT(246),
  [284] = {.entry = {.count = 1, .reusable = true}}, SHIFT(238),
  [286] = {.entry = {.count = 1, .reusable = true}}, SHIFT(228),
  [288] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [290] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [292] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [294] = {.entry = {.count = 1, .reusable = true}}, SHIFT(156),
  [296] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [298] = {.entry = {.count = 1, .reusable = true}}, SHIFT(150),
  [300] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [302] = {.entry = {.count = 1, .reusable = true}}, SHIFT(148),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(145),
  [308] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [312] = {.entry = {.count = 1, .reusable = true}}, SHIFT(142),
  [314] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [316] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [318] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [320] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [322] = {.entry = {.count = 1, .reusable = true}}, SHIFT(208),
  [324] = {.entry = {.count = 1, .reusable = true}}, SHIFT(207),
  [326] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [328] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [330] = {.entry = {.count = 1, .reusable = true}}, SHIFT(174),
  [332] = {.entry = {.count = 1, .reusable = false}}, SHIFT(174),
  [334] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 4),
  [336] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 4),
  [338] = {.entry = {.count = 1, .reusable = true}}, SHIFT(123),
  [340] = {.entry = {.count = 1, .reusable = true}}, SHIFT(173),
  [342] = {.entry = {.count = 1, .reusable = false}}, SHIFT(173),
  [344] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [346] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [348] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [350] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [352] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [354] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [356] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 12),
  [358] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 12),
  [360] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 5, .production_id = 10),
  [362] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 5, .production_id = 10),
  [364] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_numberlike_field, 1),
  [366] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_numberlike_field, 1),
  [368] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_numberlike_field, 4, .production_id = 7),
  [370] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_numberlike_field, 4, .production_id = 7),
  [372] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [374] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [376] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [378] = {.entry = {.count = 1, .reusable = true}}, SHIFT(170),
  [380] = {.entry = {.count = 1, .reusable = false}}, SHIFT(170),
  [382] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [384] = {.entry = {.count = 1, .reusable = true}}, SHIFT(178),
  [386] = {.entry = {.count = 1, .reusable = false}}, SHIFT(178),
  [388] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 4),
  [390] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 4),
  [392] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [394] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [396] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [398] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(9),
  [401] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [403] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [405] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [407] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [409] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2),
  [411] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2), SHIFT_REPEAT(91),
  [414] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 2),
  [416] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [418] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [420] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [422] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 1),
  [424] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 5, .production_id = 8),
  [426] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [428] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [430] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [432] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [434] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [436] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [438] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [440] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [442] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [444] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(104),
  [447] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [449] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(105),
  [452] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 1),
  [454] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 1),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [458] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [460] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [462] = {.entry = {.count = 1, .reusable = true}}, SHIFT(131),
  [464] = {.entry = {.count = 1, .reusable = false}}, SHIFT(171),
  [466] = {.entry = {.count = 1, .reusable = false}}, SHIFT(161),
  [468] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 4, .production_id = 3),
  [470] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 4, .production_id = 3),
  [472] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 5),
  [474] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 5),
  [476] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 3),
  [478] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 3),
  [480] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 1),
  [482] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 1),
  [484] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_number_field, 1),
  [486] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_number_field, 1),
  [488] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [490] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [492] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [494] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 8, .production_id = 20),
  [496] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 8, .production_id = 20),
  [498] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 9),
  [500] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 9),
  [502] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [504] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [506] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 11),
  [508] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 11),
  [510] = {.entry = {.count = 1, .reusable = true}}, SHIFT(216),
  [512] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [514] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 14),
  [516] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 14),
  [518] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [520] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 15),
  [522] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 15),
  [524] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_array, 6, .production_id = 17),
  [526] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_array, 6, .production_id = 17),
  [528] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [530] = {.entry = {.count = 1, .reusable = false}}, SHIFT(160),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(166),
  [534] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [536] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(164),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [544] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [546] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [548] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [550] = {.entry = {.count = 1, .reusable = true}}, SHIFT(167),
  [552] = {.entry = {.count = 1, .reusable = true}}, SHIFT(168),
  [554] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [556] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [558] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [560] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [562] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [564] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [566] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [568] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [570] = {.entry = {.count = 1, .reusable = true}}, SHIFT(220),
  [572] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [574] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [576] = {.entry = {.count = 1, .reusable = true}}, SHIFT(185),
  [578] = {.entry = {.count = 1, .reusable = true}}, SHIFT(175),
  [580] = {.entry = {.count = 1, .reusable = true}}, SHIFT(176),
  [582] = {.entry = {.count = 1, .reusable = true}}, SHIFT(186),
  [584] = {.entry = {.count = 1, .reusable = true}}, SHIFT(187),
  [586] = {.entry = {.count = 1, .reusable = true}}, SHIFT(188),
  [588] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [590] = {.entry = {.count = 1, .reusable = true}}, SHIFT(132),
  [592] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [594] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [596] = {.entry = {.count = 1, .reusable = true}}, SHIFT(192),
  [598] = {.entry = {.count = 1, .reusable = true}}, SHIFT(177),
  [600] = {.entry = {.count = 1, .reusable = true}}, SHIFT(153),
  [602] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [604] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [608] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [610] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [612] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [614] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(194),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(195),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [624] = {.entry = {.count = 1, .reusable = true}}, SHIFT(171),
  [626] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [628] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [630] = {.entry = {.count = 1, .reusable = true}}, SHIFT(197),
  [632] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [634] = {.entry = {.count = 1, .reusable = true}}, SHIFT(146),
  [636] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [638] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [640] = {.entry = {.count = 1, .reusable = true}}, SHIFT(143),
  [642] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [644] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [646] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [648] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [650] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [652] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [654] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [656] = {.entry = {.count = 1, .reusable = true}}, SHIFT(136),
  [658] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [660] = {.entry = {.count = 1, .reusable = true}}, SHIFT(134),
  [662] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [664] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [666] = {.entry = {.count = 1, .reusable = true}}, SHIFT(111),
  [668] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [670] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [672] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [674] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [676] = {.entry = {.count = 1, .reusable = true}}, SHIFT(122),
  [678] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [680] = {.entry = {.count = 1, .reusable = true}}, SHIFT(128),
  [682] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [684] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [686] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [688] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [690] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [692] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [694] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [696] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [698] = {.entry = {.count = 1, .reusable = true}}, SHIFT(223),
  [700] = {.entry = {.count = 1, .reusable = true}}, SHIFT(224),
  [702] = {.entry = {.count = 1, .reusable = true}}, SHIFT(225),
  [704] = {.entry = {.count = 1, .reusable = true}}, SHIFT(226),
  [706] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [708] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [710] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [712] = {.entry = {.count = 1, .reusable = true}}, SHIFT(233),
  [714] = {.entry = {.count = 1, .reusable = true}}, SHIFT(234),
  [716] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [718] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [720] = {.entry = {.count = 1, .reusable = true}}, SHIFT(235),
  [722] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [724] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [726] = {.entry = {.count = 1, .reusable = true}}, SHIFT(244),
  [728] = {.entry = {.count = 1, .reusable = true}}, SHIFT(247),
  [730] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [732] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef _WIN32
#define extern __declspec(dllexport)
#endif

extern const TSLanguage *tree_sitter_cloudflare(void) {
  static const TSLanguage language = {
    .version = LANGUAGE_VERSION,
    .symbol_count = SYMBOL_COUNT,
    .alias_count = ALIAS_COUNT,
    .token_count = TOKEN_COUNT,
    .external_token_count = EXTERNAL_TOKEN_COUNT,
    .state_count = STATE_COUNT,
    .large_state_count = LARGE_STATE_COUNT,
    .production_id_count = PRODUCTION_ID_COUNT,
    .field_count = FIELD_COUNT,
    .max_alias_sequence_length = MAX_ALIAS_SEQUENCE_LENGTH,
    .parse_table = &ts_parse_table[0][0],
    .small_parse_table = ts_small_parse_table,
    .small_parse_table_map = ts_small_parse_table_map,
    .parse_actions = ts_parse_actions,
    .symbol_names = ts_symbol_names,
    .field_names = ts_field_names,
    .field_map_slices = ts_field_map_slices,
    .field_map_entries = ts_field_map_entries,
    .symbol_metadata = ts_symbol_metadata,
    .public_symbol_map = ts_symbol_map,
    .alias_map = ts_non_terminal_alias_map,
    .alias_sequences = &ts_alias_sequences[0][0],
    .lex_modes = ts_lex_modes,
    .lex_fn = ts_lex,
    .primary_state_ids = ts_primary_state_ids,
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
