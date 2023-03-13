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
#define STATE_COUNT 330
#define LARGE_STATE_COUNT 90
#define SYMBOL_COUNT 201
#define ALIAS_COUNT 0
#define TOKEN_COUNT 159
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 16
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 31

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
  sym__boollike_field = 184,
  sym__numberlike_field = 185,
  sym__stringlike_field = 186,
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
  [sym__boollike_field] = "_boollike_field",
  [sym__numberlike_field] = "_numberlike_field",
  [sym__stringlike_field] = "_stringlike_field",
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
  [sym__boollike_field] = sym__boollike_field,
  [sym__numberlike_field] = sym__numberlike_field,
  [sym__stringlike_field] = sym__stringlike_field,
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
  [sym__boollike_field] = {
    .visible = false,
    .named = true,
  },
  [sym__numberlike_field] = {
    .visible = false,
    .named = true,
  },
  [sym__stringlike_field] = {
    .visible = false,
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
  [2] = {.index = 1, .length = 1},
  [3] = {.index = 2, .length = 2},
  [4] = {.index = 4, .length = 2},
  [5] = {.index = 6, .length = 5},
  [6] = {.index = 11, .length = 4},
  [7] = {.index = 15, .length = 3},
  [8] = {.index = 18, .length = 3},
  [9] = {.index = 21, .length = 3},
  [10] = {.index = 24, .length = 2},
  [11] = {.index = 26, .length = 3},
  [12] = {.index = 29, .length = 3},
  [13] = {.index = 32, .length = 1},
  [14] = {.index = 33, .length = 1},
  [15] = {.index = 34, .length = 4},
  [16] = {.index = 38, .length = 4},
  [17] = {.index = 42, .length = 3},
  [18] = {.index = 45, .length = 1},
  [19] = {.index = 46, .length = 2},
  [20] = {.index = 48, .length = 2},
  [21] = {.index = 50, .length = 3},
  [22] = {.index = 53, .length = 3},
  [23] = {.index = 56, .length = 4},
  [24] = {.index = 60, .length = 4},
  [25] = {.index = 64, .length = 3},
  [26] = {.index = 67, .length = 4},
  [27] = {.index = 71, .length = 4},
  [28] = {.index = 75, .length = 5},
  [29] = {.index = 80, .length = 5},
  [30] = {.index = 85, .length = 5},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_index, 0, .inherited = true},
  [1] =
    {field_index, 1, .inherited = true},
  [2] =
    {field_index, 0, .inherited = true},
    {field_index, 1, .inherited = true},
  [4] =
    {field_index, 1, .inherited = true},
    {field_inner, 1},
  [6] =
    {field_index, 0, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [11] =
    {field_index, 0, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [15] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [18] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
  [21] =
    {field_field, 2},
    {field_func, 0},
    {field_index, 2, .inherited = true},
  [24] =
    {field_field, 2},
    {field_func, 0},
  [26] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_seed, 2},
  [29] =
    {field_func, 0},
    {field_index, 2, .inherited = true},
    {field_seed, 2},
  [32] =
    {field_index, 2},
  [33] =
    {field_key, 2},
  [34] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_keys, 3},
  [38] =
    {field_field, 2},
    {field_func, 0},
    {field_index, 2, .inherited = true},
    {field_keys, 3},
  [42] =
    {field_field, 2},
    {field_field, 3},
    {field_func, 0},
  [45] =
    {field_func, 0},
  [46] =
    {field_ip, 0},
    {field_mask, 2},
  [48] =
    {field_func, 0},
    {field_index, 4, .inherited = true},
  [50] =
    {field_func, 0},
    {field_index, 4, .inherited = true},
    {field_key, 2, .inherited = true},
  [53] =
    {field_func, 0},
    {field_index, 2, .inherited = true},
    {field_index, 4, .inherited = true},
  [56] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_replacement, 4},
  [60] =
    {field_field, 2},
    {field_func, 0},
    {field_index, 2, .inherited = true},
    {field_replacement, 4},
  [64] =
    {field_field, 2},
    {field_func, 0},
    {field_replacement, 4},
  [67] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_value, 4},
  [71] =
    {field_field, 2},
    {field_func, 0},
    {field_index, 2, .inherited = true},
    {field_value, 4},
  [75] =
    {field_func, 0},
    {field_lhs, 2},
    {field_lhs, 3},
    {field_operator, 4},
    {field_rhs, 5},
  [80] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
  [85] =
    {field_func, 0},
    {field_index, 2, .inherited = true},
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
  [36] = 36,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 43,
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
  [58] = 58,
  [59] = 59,
  [60] = 60,
  [61] = 61,
  [62] = 62,
  [63] = 63,
  [64] = 64,
  [65] = 65,
  [66] = 66,
  [67] = 67,
  [68] = 68,
  [69] = 69,
  [70] = 70,
  [71] = 71,
  [72] = 70,
  [73] = 73,
  [74] = 74,
  [75] = 75,
  [76] = 76,
  [77] = 77,
  [78] = 76,
  [79] = 79,
  [80] = 80,
  [81] = 81,
  [82] = 82,
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
  [95] = 95,
  [96] = 96,
  [97] = 97,
  [98] = 98,
  [99] = 99,
  [100] = 98,
  [101] = 93,
  [102] = 94,
  [103] = 99,
  [104] = 92,
  [105] = 95,
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
  [129] = 127,
  [130] = 130,
  [131] = 131,
  [132] = 132,
  [133] = 133,
  [134] = 134,
  [135] = 135,
  [136] = 136,
  [137] = 137,
  [138] = 135,
  [139] = 139,
  [140] = 140,
  [141] = 141,
  [142] = 142,
  [143] = 143,
  [144] = 144,
  [145] = 145,
  [146] = 142,
  [147] = 147,
  [148] = 148,
  [149] = 149,
  [150] = 150,
  [151] = 151,
  [152] = 152,
  [153] = 153,
  [154] = 154,
  [155] = 155,
  [156] = 156,
  [157] = 157,
  [158] = 158,
  [159] = 159,
  [160] = 160,
  [161] = 161,
  [162] = 162,
  [163] = 163,
  [164] = 164,
  [165] = 165,
  [166] = 166,
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
  [180] = 180,
  [181] = 181,
  [182] = 182,
  [183] = 183,
  [184] = 184,
  [185] = 185,
  [186] = 186,
  [187] = 187,
  [188] = 188,
  [189] = 189,
  [190] = 190,
  [191] = 191,
  [192] = 192,
  [193] = 193,
  [194] = 165,
  [195] = 195,
  [196] = 196,
  [197] = 197,
  [198] = 198,
  [199] = 199,
  [200] = 200,
  [201] = 201,
  [202] = 202,
  [203] = 203,
  [204] = 204,
  [205] = 205,
  [206] = 206,
  [207] = 164,
  [208] = 208,
  [209] = 163,
  [210] = 210,
  [211] = 211,
  [212] = 212,
  [213] = 213,
  [214] = 214,
  [215] = 215,
  [216] = 216,
  [217] = 217,
  [218] = 218,
  [219] = 219,
  [220] = 220,
  [221] = 221,
  [222] = 222,
  [223] = 223,
  [224] = 162,
  [225] = 225,
  [226] = 226,
  [227] = 227,
  [228] = 228,
  [229] = 229,
  [230] = 230,
  [231] = 231,
  [232] = 232,
  [233] = 233,
  [234] = 161,
  [235] = 235,
  [236] = 236,
  [237] = 237,
  [238] = 238,
  [239] = 239,
  [240] = 240,
  [241] = 241,
  [242] = 160,
  [243] = 243,
  [244] = 244,
  [245] = 245,
  [246] = 246,
  [247] = 247,
  [248] = 248,
  [249] = 249,
  [250] = 250,
  [251] = 251,
  [252] = 252,
  [253] = 253,
  [254] = 254,
  [255] = 255,
  [256] = 256,
  [257] = 257,
  [258] = 258,
  [259] = 259,
  [260] = 166,
  [261] = 159,
  [262] = 167,
  [263] = 263,
  [264] = 264,
  [265] = 265,
  [266] = 158,
  [267] = 267,
  [268] = 268,
  [269] = 157,
  [270] = 270,
  [271] = 271,
  [272] = 272,
  [273] = 273,
  [274] = 274,
  [275] = 275,
  [276] = 155,
  [277] = 168,
  [278] = 278,
  [279] = 279,
  [280] = 280,
  [281] = 281,
  [282] = 282,
  [283] = 283,
  [284] = 284,
  [285] = 285,
  [286] = 286,
  [287] = 287,
  [288] = 288,
  [289] = 289,
  [290] = 290,
  [291] = 291,
  [292] = 186,
  [293] = 283,
  [294] = 285,
  [295] = 181,
  [296] = 171,
  [297] = 297,
  [298] = 298,
  [299] = 203,
  [300] = 226,
  [301] = 301,
  [302] = 239,
  [303] = 243,
  [304] = 273,
  [305] = 205,
  [306] = 289,
  [307] = 191,
  [308] = 308,
  [309] = 309,
  [310] = 310,
  [311] = 311,
  [312] = 198,
  [313] = 212,
  [314] = 264,
  [315] = 267,
  [316] = 202,
  [317] = 192,
  [318] = 189,
  [319] = 182,
  [320] = 288,
  [321] = 321,
  [322] = 322,
  [323] = 237,
  [324] = 204,
  [325] = 193,
  [326] = 196,
  [327] = 184,
  [328] = 328,
  [329] = 195,
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
  [31] = {.lex_state = 949},
  [32] = {.lex_state = 949},
  [33] = {.lex_state = 949},
  [34] = {.lex_state = 949},
  [35] = {.lex_state = 949},
  [36] = {.lex_state = 949},
  [37] = {.lex_state = 949},
  [38] = {.lex_state = 949},
  [39] = {.lex_state = 949},
  [40] = {.lex_state = 949},
  [41] = {.lex_state = 949},
  [42] = {.lex_state = 949},
  [43] = {.lex_state = 949},
  [44] = {.lex_state = 949},
  [45] = {.lex_state = 949},
  [46] = {.lex_state = 949},
  [47] = {.lex_state = 949},
  [48] = {.lex_state = 949},
  [49] = {.lex_state = 949},
  [50] = {.lex_state = 949},
  [51] = {.lex_state = 949},
  [52] = {.lex_state = 949},
  [53] = {.lex_state = 949},
  [54] = {.lex_state = 949},
  [55] = {.lex_state = 949},
  [56] = {.lex_state = 949},
  [57] = {.lex_state = 949},
  [58] = {.lex_state = 949},
  [59] = {.lex_state = 949},
  [60] = {.lex_state = 949},
  [61] = {.lex_state = 949},
  [62] = {.lex_state = 949},
  [63] = {.lex_state = 949},
  [64] = {.lex_state = 949},
  [65] = {.lex_state = 949},
  [66] = {.lex_state = 949},
  [67] = {.lex_state = 1},
  [68] = {.lex_state = 1},
  [69] = {.lex_state = 0},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 0},
  [74] = {.lex_state = 0},
  [75] = {.lex_state = 0},
  [76] = {.lex_state = 0},
  [77] = {.lex_state = 0},
  [78] = {.lex_state = 0},
  [79] = {.lex_state = 0},
  [80] = {.lex_state = 0},
  [81] = {.lex_state = 0},
  [82] = {.lex_state = 0},
  [83] = {.lex_state = 0},
  [84] = {.lex_state = 0},
  [85] = {.lex_state = 0},
  [86] = {.lex_state = 0},
  [87] = {.lex_state = 0},
  [88] = {.lex_state = 0},
  [89] = {.lex_state = 0},
  [90] = {.lex_state = 949},
  [91] = {.lex_state = 949},
  [92] = {.lex_state = 0},
  [93] = {.lex_state = 0},
  [94] = {.lex_state = 0},
  [95] = {.lex_state = 0},
  [96] = {.lex_state = 0},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 0},
  [99] = {.lex_state = 0},
  [100] = {.lex_state = 0},
  [101] = {.lex_state = 0},
  [102] = {.lex_state = 0},
  [103] = {.lex_state = 0},
  [104] = {.lex_state = 0},
  [105] = {.lex_state = 0},
  [106] = {.lex_state = 1},
  [107] = {.lex_state = 1},
  [108] = {.lex_state = 1},
  [109] = {.lex_state = 1},
  [110] = {.lex_state = 1},
  [111] = {.lex_state = 1},
  [112] = {.lex_state = 1},
  [113] = {.lex_state = 1},
  [114] = {.lex_state = 1},
  [115] = {.lex_state = 1},
  [116] = {.lex_state = 1},
  [117] = {.lex_state = 1},
  [118] = {.lex_state = 1},
  [119] = {.lex_state = 1},
  [120] = {.lex_state = 1},
  [121] = {.lex_state = 1},
  [122] = {.lex_state = 1},
  [123] = {.lex_state = 1},
  [124] = {.lex_state = 1},
  [125] = {.lex_state = 1},
  [126] = {.lex_state = 1},
  [127] = {.lex_state = 949},
  [128] = {.lex_state = 0},
  [129] = {.lex_state = 949},
  [130] = {.lex_state = 1},
  [131] = {.lex_state = 1},
  [132] = {.lex_state = 949},
  [133] = {.lex_state = 949},
  [134] = {.lex_state = 1},
  [135] = {.lex_state = 1},
  [136] = {.lex_state = 1},
  [137] = {.lex_state = 1},
  [138] = {.lex_state = 1},
  [139] = {.lex_state = 949},
  [140] = {.lex_state = 1},
  [141] = {.lex_state = 1},
  [142] = {.lex_state = 1},
  [143] = {.lex_state = 1},
  [144] = {.lex_state = 949},
  [145] = {.lex_state = 1},
  [146] = {.lex_state = 1},
  [147] = {.lex_state = 1},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 1},
  [152] = {.lex_state = 0},
  [153] = {.lex_state = 0},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 0},
  [156] = {.lex_state = 1},
  [157] = {.lex_state = 0},
  [158] = {.lex_state = 0},
  [159] = {.lex_state = 0},
  [160] = {.lex_state = 0},
  [161] = {.lex_state = 0},
  [162] = {.lex_state = 0},
  [163] = {.lex_state = 0},
  [164] = {.lex_state = 0},
  [165] = {.lex_state = 0},
  [166] = {.lex_state = 0},
  [167] = {.lex_state = 0},
  [168] = {.lex_state = 0},
  [169] = {.lex_state = 0},
  [170] = {.lex_state = 0},
  [171] = {.lex_state = 0},
  [172] = {.lex_state = 0},
  [173] = {.lex_state = 0},
  [174] = {.lex_state = 0},
  [175] = {.lex_state = 0},
  [176] = {.lex_state = 0},
  [177] = {.lex_state = 0},
  [178] = {.lex_state = 1},
  [179] = {.lex_state = 0},
  [180] = {.lex_state = 0},
  [181] = {.lex_state = 0},
  [182] = {.lex_state = 0},
  [183] = {.lex_state = 0},
  [184] = {.lex_state = 0},
  [185] = {.lex_state = 0},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 949},
  [188] = {.lex_state = 0},
  [189] = {.lex_state = 0},
  [190] = {.lex_state = 0},
  [191] = {.lex_state = 0},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 0},
  [194] = {.lex_state = 949},
  [195] = {.lex_state = 0},
  [196] = {.lex_state = 0},
  [197] = {.lex_state = 0},
  [198] = {.lex_state = 0},
  [199] = {.lex_state = 0},
  [200] = {.lex_state = 0},
  [201] = {.lex_state = 0},
  [202] = {.lex_state = 0},
  [203] = {.lex_state = 0},
  [204] = {.lex_state = 0},
  [205] = {.lex_state = 0},
  [206] = {.lex_state = 1},
  [207] = {.lex_state = 949},
  [208] = {.lex_state = 1},
  [209] = {.lex_state = 949},
  [210] = {.lex_state = 1},
  [211] = {.lex_state = 0},
  [212] = {.lex_state = 0},
  [213] = {.lex_state = 0},
  [214] = {.lex_state = 0},
  [215] = {.lex_state = 0},
  [216] = {.lex_state = 0},
  [217] = {.lex_state = 0},
  [218] = {.lex_state = 0},
  [219] = {.lex_state = 0},
  [220] = {.lex_state = 0},
  [221] = {.lex_state = 0},
  [222] = {.lex_state = 0},
  [223] = {.lex_state = 3},
  [224] = {.lex_state = 949},
  [225] = {.lex_state = 0},
  [226] = {.lex_state = 0},
  [227] = {.lex_state = 0},
  [228] = {.lex_state = 0},
  [229] = {.lex_state = 0},
  [230] = {.lex_state = 0},
  [231] = {.lex_state = 0},
  [232] = {.lex_state = 0},
  [233] = {.lex_state = 0},
  [234] = {.lex_state = 949},
  [235] = {.lex_state = 0},
  [236] = {.lex_state = 1},
  [237] = {.lex_state = 0},
  [238] = {.lex_state = 0},
  [239] = {.lex_state = 0},
  [240] = {.lex_state = 0},
  [241] = {.lex_state = 0},
  [242] = {.lex_state = 949},
  [243] = {.lex_state = 0},
  [244] = {.lex_state = 0},
  [245] = {.lex_state = 1},
  [246] = {.lex_state = 1},
  [247] = {.lex_state = 1},
  [248] = {.lex_state = 0},
  [249] = {.lex_state = 0},
  [250] = {.lex_state = 1},
  [251] = {.lex_state = 1},
  [252] = {.lex_state = 1},
  [253] = {.lex_state = 1},
  [254] = {.lex_state = 0},
  [255] = {.lex_state = 1},
  [256] = {.lex_state = 1},
  [257] = {.lex_state = 1},
  [258] = {.lex_state = 1},
  [259] = {.lex_state = 0},
  [260] = {.lex_state = 949},
  [261] = {.lex_state = 949},
  [262] = {.lex_state = 949},
  [263] = {.lex_state = 0},
  [264] = {.lex_state = 0},
  [265] = {.lex_state = 0},
  [266] = {.lex_state = 949},
  [267] = {.lex_state = 949},
  [268] = {.lex_state = 949},
  [269] = {.lex_state = 949},
  [270] = {.lex_state = 949},
  [271] = {.lex_state = 0},
  [272] = {.lex_state = 949},
  [273] = {.lex_state = 0},
  [274] = {.lex_state = 0},
  [275] = {.lex_state = 0},
  [276] = {.lex_state = 949},
  [277] = {.lex_state = 949},
  [278] = {.lex_state = 0},
  [279] = {.lex_state = 0},
  [280] = {.lex_state = 0},
  [281] = {.lex_state = 0},
  [282] = {.lex_state = 0},
  [283] = {.lex_state = 0},
  [284] = {.lex_state = 0},
  [285] = {.lex_state = 0},
  [286] = {.lex_state = 0},
  [287] = {.lex_state = 0},
  [288] = {.lex_state = 0},
  [289] = {.lex_state = 0},
  [290] = {.lex_state = 0},
  [291] = {.lex_state = 0},
  [292] = {.lex_state = 0},
  [293] = {.lex_state = 0},
  [294] = {.lex_state = 0},
  [295] = {.lex_state = 0},
  [296] = {.lex_state = 949},
  [297] = {.lex_state = 949},
  [298] = {.lex_state = 0},
  [299] = {.lex_state = 0},
  [300] = {.lex_state = 0},
  [301] = {.lex_state = 0},
  [302] = {.lex_state = 0},
  [303] = {.lex_state = 0},
  [304] = {.lex_state = 0},
  [305] = {.lex_state = 0},
  [306] = {.lex_state = 0},
  [307] = {.lex_state = 0},
  [308] = {.lex_state = 0},
  [309] = {.lex_state = 0},
  [310] = {.lex_state = 0},
  [311] = {.lex_state = 0},
  [312] = {.lex_state = 0},
  [313] = {.lex_state = 0},
  [314] = {.lex_state = 0},
  [315] = {.lex_state = 949},
  [316] = {.lex_state = 0},
  [317] = {.lex_state = 0},
  [318] = {.lex_state = 0},
  [319] = {.lex_state = 0},
  [320] = {.lex_state = 0},
  [321] = {.lex_state = 0},
  [322] = {.lex_state = 0},
  [323] = {.lex_state = 0},
  [324] = {.lex_state = 0},
  [325] = {.lex_state = 0},
  [326] = {.lex_state = 0},
  [327] = {.lex_state = 0},
  [328] = {.lex_state = 0},
  [329] = {.lex_state = 0},
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
    [sym_source_file] = STATE(275),
    [sym__expression] = STATE(65),
    [sym_not_expression] = STATE(65),
    [sym_in_expression] = STATE(65),
    [sym_compound_expression] = STATE(65),
    [sym_simple_expression] = STATE(65),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(65),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(65),
    [sym_not_expression] = STATE(65),
    [sym_in_expression] = STATE(65),
    [sym_compound_expression] = STATE(65),
    [sym_simple_expression] = STATE(65),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(65),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(65),
    [sym_not_expression] = STATE(65),
    [sym_in_expression] = STATE(65),
    [sym_compound_expression] = STATE(65),
    [sym_simple_expression] = STATE(65),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(65),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(64),
    [sym_not_expression] = STATE(64),
    [sym_in_expression] = STATE(64),
    [sym_compound_expression] = STATE(64),
    [sym_simple_expression] = STATE(64),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(64),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(128),
    [sym_not_expression] = STATE(128),
    [sym_in_expression] = STATE(128),
    [sym_compound_expression] = STATE(128),
    [sym_simple_expression] = STATE(128),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(128),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(27),
    [sym_not_expression] = STATE(27),
    [sym_in_expression] = STATE(27),
    [sym_compound_expression] = STATE(27),
    [sym_simple_expression] = STATE(27),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(27),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(30),
    [sym_not_expression] = STATE(30),
    [sym_in_expression] = STATE(30),
    [sym_compound_expression] = STATE(30),
    [sym_simple_expression] = STATE(30),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(30),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(31),
    [sym_not_expression] = STATE(31),
    [sym_in_expression] = STATE(31),
    [sym_compound_expression] = STATE(31),
    [sym_simple_expression] = STATE(31),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(31),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
    [sym__expression] = STATE(33),
    [sym_not_expression] = STATE(33),
    [sym_in_expression] = STATE(33),
    [sym_compound_expression] = STATE(33),
    [sym_simple_expression] = STATE(33),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(33),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
  [10] = {
    [sym__expression] = STATE(34),
    [sym_not_expression] = STATE(34),
    [sym_in_expression] = STATE(34),
    [sym_compound_expression] = STATE(34),
    [sym_simple_expression] = STATE(34),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(34),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
  [11] = {
    [sym__expression] = STATE(35),
    [sym_not_expression] = STATE(35),
    [sym_in_expression] = STATE(35),
    [sym_compound_expression] = STATE(35),
    [sym_simple_expression] = STATE(35),
    [sym__bool_lhs] = STATE(25),
    [sym__number_lhs] = STATE(125),
    [sym__string_lhs] = STATE(110),
    [sym_string_func] = STATE(110),
    [sym_number_func] = STATE(125),
    [sym_bool_func] = STATE(25),
    [sym_array_func] = STATE(28),
    [sym_group] = STATE(35),
    [sym_boolean] = STATE(25),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(272),
    [sym_bool_array] = STATE(270),
    [sym_string_array] = STATE(268),
    [sym__boollike_field] = STATE(32),
    [sym__numberlike_field] = STATE(122),
    [sym__stringlike_field] = STATE(113),
    [sym_number_field] = STATE(122),
    [sym_ip_field] = STATE(131),
    [sym_string_field] = STATE(113),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [sym_array_number_field] = STATE(260),
    [sym_bool_field] = STATE(32),
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
  [12] = {
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
  [13] = {
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
  [14] = {
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
  [15] = {
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
  [16] = {
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
  [17] = {
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
  [18] = {
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
  [19] = {
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
  [20] = {
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
  [21] = {
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
  [22] = {
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
  [23] = {
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
  [24] = {
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
  [25] = {
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
  [26] = {
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
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(173),
    [anon_sym_xor] = ACTIONS(175),
    [anon_sym_CARET_CARET] = ACTIONS(177),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [28] = {
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
  [29] = {
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
  [30] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(173),
    [anon_sym_xor] = ACTIONS(175),
    [anon_sym_CARET_CARET] = ACTIONS(177),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [31] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(173),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [32] = {
    [ts_builtin_sym_end] = ACTIONS(189),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(189),
    [anon_sym_xor] = ACTIONS(189),
    [anon_sym_CARET_CARET] = ACTIONS(189),
    [anon_sym_or] = ACTIONS(189),
    [anon_sym_PIPE_PIPE] = ACTIONS(189),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(189),
    [anon_sym_LPAREN] = ACTIONS(189),
    [anon_sym_RPAREN] = ACTIONS(189),
    [anon_sym_lookup_json_string] = ACTIONS(189),
    [anon_sym_lower] = ACTIONS(189),
    [anon_sym_regex_replace] = ACTIONS(189),
    [anon_sym_remove_bytes] = ACTIONS(189),
    [anon_sym_to_string] = ACTIONS(189),
    [anon_sym_upper] = ACTIONS(189),
    [anon_sym_url_decode] = ACTIONS(189),
    [anon_sym_uuidv4] = ACTIONS(189),
    [anon_sym_len] = ACTIONS(189),
    [anon_sym_ends_with] = ACTIONS(189),
    [anon_sym_starts_with] = ACTIONS(189),
    [anon_sym_any] = ACTIONS(189),
    [anon_sym_all] = ACTIONS(189),
    [anon_sym_true] = ACTIONS(189),
    [anon_sym_false] = ACTIONS(189),
    [anon_sym_not] = ACTIONS(189),
    [anon_sym_BANG] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(189),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(189),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(189),
    [anon_sym_icmp_DOTtype] = ACTIONS(189),
    [anon_sym_icmp_DOTcode] = ACTIONS(189),
    [anon_sym_ip_DOThdr_len] = ACTIONS(189),
    [anon_sym_ip_DOTlen] = ACTIONS(189),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(189),
    [anon_sym_ip_DOTttl] = ACTIONS(189),
    [anon_sym_tcp_DOTflags] = ACTIONS(191),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(189),
    [anon_sym_tcp_DOTdstport] = ACTIONS(189),
    [anon_sym_udp_DOTdstport] = ACTIONS(189),
    [anon_sym_udp_DOTsrcport] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc] = ACTIONS(191),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(189),
    [anon_sym_ip_DOTdst] = ACTIONS(191),
    [anon_sym_http_DOTcookie] = ACTIONS(189),
    [anon_sym_http_DOThost] = ACTIONS(189),
    [anon_sym_http_DOTreferer] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(189),
    [anon_sym_http_DOTuser_agent] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(189),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(189),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(189),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(189),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(189),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(189),
    [anon_sym_icmp] = ACTIONS(191),
    [anon_sym_ip] = ACTIONS(191),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(189),
    [anon_sym_tcp] = ACTIONS(191),
    [anon_sym_udp] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(189),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(189),
    [anon_sym_ssl] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(189),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(189),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(189),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(189),
    [anon_sym_sip] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(189),
  },
  [33] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(173),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [34] = {
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [35] = {
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
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
  [36] = {
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
  [37] = {
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
  [38] = {
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
  [39] = {
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
  [40] = {
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
  [41] = {
    [ts_builtin_sym_end] = ACTIONS(193),
    [anon_sym_AMP_AMP] = ACTIONS(193),
    [anon_sym_and] = ACTIONS(193),
    [anon_sym_xor] = ACTIONS(193),
    [anon_sym_CARET_CARET] = ACTIONS(193),
    [anon_sym_or] = ACTIONS(193),
    [anon_sym_PIPE_PIPE] = ACTIONS(193),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(193),
    [anon_sym_LPAREN] = ACTIONS(193),
    [anon_sym_RPAREN] = ACTIONS(193),
    [anon_sym_lookup_json_string] = ACTIONS(193),
    [anon_sym_lower] = ACTIONS(193),
    [anon_sym_regex_replace] = ACTIONS(193),
    [anon_sym_remove_bytes] = ACTIONS(193),
    [anon_sym_to_string] = ACTIONS(193),
    [anon_sym_upper] = ACTIONS(193),
    [anon_sym_url_decode] = ACTIONS(193),
    [anon_sym_uuidv4] = ACTIONS(193),
    [anon_sym_len] = ACTIONS(193),
    [anon_sym_ends_with] = ACTIONS(193),
    [anon_sym_starts_with] = ACTIONS(193),
    [anon_sym_any] = ACTIONS(193),
    [anon_sym_all] = ACTIONS(193),
    [anon_sym_true] = ACTIONS(193),
    [anon_sym_false] = ACTIONS(193),
    [anon_sym_not] = ACTIONS(193),
    [anon_sym_BANG] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(193),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(193),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(193),
    [anon_sym_icmp_DOTtype] = ACTIONS(193),
    [anon_sym_icmp_DOTcode] = ACTIONS(193),
    [anon_sym_ip_DOThdr_len] = ACTIONS(193),
    [anon_sym_ip_DOTlen] = ACTIONS(193),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(193),
    [anon_sym_ip_DOTttl] = ACTIONS(193),
    [anon_sym_tcp_DOTflags] = ACTIONS(195),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(193),
    [anon_sym_tcp_DOTdstport] = ACTIONS(193),
    [anon_sym_udp_DOTdstport] = ACTIONS(193),
    [anon_sym_udp_DOTsrcport] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc] = ACTIONS(195),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(193),
    [anon_sym_ip_DOTdst] = ACTIONS(195),
    [anon_sym_http_DOTcookie] = ACTIONS(193),
    [anon_sym_http_DOThost] = ACTIONS(193),
    [anon_sym_http_DOTreferer] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_http_DOTuser_agent] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(193),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(193),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(193),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(193),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(193),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(193),
    [anon_sym_icmp] = ACTIONS(195),
    [anon_sym_ip] = ACTIONS(195),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(193),
    [anon_sym_tcp] = ACTIONS(195),
    [anon_sym_udp] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(193),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(193),
    [anon_sym_ssl] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(193),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(193),
    [anon_sym_sip] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(193),
  },
  [42] = {
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
  [43] = {
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
  [44] = {
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
  [45] = {
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
  [46] = {
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
  [47] = {
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
  [48] = {
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
  [49] = {
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
  [50] = {
    [ts_builtin_sym_end] = ACTIONS(197),
    [anon_sym_AMP_AMP] = ACTIONS(197),
    [anon_sym_and] = ACTIONS(197),
    [anon_sym_xor] = ACTIONS(197),
    [anon_sym_CARET_CARET] = ACTIONS(197),
    [anon_sym_or] = ACTIONS(197),
    [anon_sym_PIPE_PIPE] = ACTIONS(197),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(197),
    [anon_sym_LPAREN] = ACTIONS(197),
    [anon_sym_RPAREN] = ACTIONS(197),
    [anon_sym_lookup_json_string] = ACTIONS(197),
    [anon_sym_lower] = ACTIONS(197),
    [anon_sym_regex_replace] = ACTIONS(197),
    [anon_sym_remove_bytes] = ACTIONS(197),
    [anon_sym_to_string] = ACTIONS(197),
    [anon_sym_upper] = ACTIONS(197),
    [anon_sym_url_decode] = ACTIONS(197),
    [anon_sym_uuidv4] = ACTIONS(197),
    [anon_sym_len] = ACTIONS(197),
    [anon_sym_ends_with] = ACTIONS(197),
    [anon_sym_starts_with] = ACTIONS(197),
    [anon_sym_any] = ACTIONS(197),
    [anon_sym_all] = ACTIONS(197),
    [anon_sym_true] = ACTIONS(197),
    [anon_sym_false] = ACTIONS(197),
    [anon_sym_not] = ACTIONS(197),
    [anon_sym_BANG] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(197),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(197),
    [anon_sym_icmp_DOTtype] = ACTIONS(197),
    [anon_sym_icmp_DOTcode] = ACTIONS(197),
    [anon_sym_ip_DOThdr_len] = ACTIONS(197),
    [anon_sym_ip_DOTlen] = ACTIONS(197),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(197),
    [anon_sym_ip_DOTttl] = ACTIONS(197),
    [anon_sym_tcp_DOTflags] = ACTIONS(199),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(197),
    [anon_sym_tcp_DOTdstport] = ACTIONS(197),
    [anon_sym_udp_DOTdstport] = ACTIONS(197),
    [anon_sym_udp_DOTsrcport] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc] = ACTIONS(199),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(197),
    [anon_sym_ip_DOTdst] = ACTIONS(199),
    [anon_sym_http_DOTcookie] = ACTIONS(197),
    [anon_sym_http_DOThost] = ACTIONS(197),
    [anon_sym_http_DOTreferer] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_http_DOTuser_agent] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(197),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(197),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(197),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(197),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(197),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(197),
    [anon_sym_icmp] = ACTIONS(199),
    [anon_sym_ip] = ACTIONS(199),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(197),
    [anon_sym_tcp] = ACTIONS(199),
    [anon_sym_udp] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(197),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(197),
    [anon_sym_ssl] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(197),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(197),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(197),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(197),
    [anon_sym_sip] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(197),
  },
  [51] = {
    [ts_builtin_sym_end] = ACTIONS(201),
    [anon_sym_AMP_AMP] = ACTIONS(201),
    [anon_sym_and] = ACTIONS(201),
    [anon_sym_xor] = ACTIONS(201),
    [anon_sym_CARET_CARET] = ACTIONS(201),
    [anon_sym_or] = ACTIONS(201),
    [anon_sym_PIPE_PIPE] = ACTIONS(201),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(201),
    [anon_sym_LPAREN] = ACTIONS(201),
    [anon_sym_RPAREN] = ACTIONS(201),
    [anon_sym_lookup_json_string] = ACTIONS(201),
    [anon_sym_lower] = ACTIONS(201),
    [anon_sym_regex_replace] = ACTIONS(201),
    [anon_sym_remove_bytes] = ACTIONS(201),
    [anon_sym_to_string] = ACTIONS(201),
    [anon_sym_upper] = ACTIONS(201),
    [anon_sym_url_decode] = ACTIONS(201),
    [anon_sym_uuidv4] = ACTIONS(201),
    [anon_sym_len] = ACTIONS(201),
    [anon_sym_ends_with] = ACTIONS(201),
    [anon_sym_starts_with] = ACTIONS(201),
    [anon_sym_any] = ACTIONS(201),
    [anon_sym_all] = ACTIONS(201),
    [anon_sym_true] = ACTIONS(201),
    [anon_sym_false] = ACTIONS(201),
    [anon_sym_not] = ACTIONS(201),
    [anon_sym_BANG] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(201),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(201),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(201),
    [anon_sym_icmp_DOTtype] = ACTIONS(201),
    [anon_sym_icmp_DOTcode] = ACTIONS(201),
    [anon_sym_ip_DOThdr_len] = ACTIONS(201),
    [anon_sym_ip_DOTlen] = ACTIONS(201),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(201),
    [anon_sym_ip_DOTttl] = ACTIONS(201),
    [anon_sym_tcp_DOTflags] = ACTIONS(203),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(201),
    [anon_sym_tcp_DOTdstport] = ACTIONS(201),
    [anon_sym_udp_DOTdstport] = ACTIONS(201),
    [anon_sym_udp_DOTsrcport] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc] = ACTIONS(203),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(201),
    [anon_sym_ip_DOTdst] = ACTIONS(203),
    [anon_sym_http_DOTcookie] = ACTIONS(201),
    [anon_sym_http_DOThost] = ACTIONS(201),
    [anon_sym_http_DOTreferer] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_http_DOTuser_agent] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(201),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(201),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(201),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(201),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(201),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(201),
    [anon_sym_icmp] = ACTIONS(203),
    [anon_sym_ip] = ACTIONS(203),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(201),
    [anon_sym_tcp] = ACTIONS(203),
    [anon_sym_udp] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(201),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(201),
    [anon_sym_ssl] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(201),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(201),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(201),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(201),
    [anon_sym_sip] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(201),
  },
  [52] = {
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
  [53] = {
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
  [54] = {
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
  [55] = {
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
  [56] = {
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
  [57] = {
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
  [58] = {
    [ts_builtin_sym_end] = ACTIONS(205),
    [anon_sym_AMP_AMP] = ACTIONS(205),
    [anon_sym_and] = ACTIONS(205),
    [anon_sym_xor] = ACTIONS(205),
    [anon_sym_CARET_CARET] = ACTIONS(205),
    [anon_sym_or] = ACTIONS(205),
    [anon_sym_PIPE_PIPE] = ACTIONS(205),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(205),
    [anon_sym_LPAREN] = ACTIONS(205),
    [anon_sym_RPAREN] = ACTIONS(205),
    [anon_sym_lookup_json_string] = ACTIONS(205),
    [anon_sym_lower] = ACTIONS(205),
    [anon_sym_regex_replace] = ACTIONS(205),
    [anon_sym_remove_bytes] = ACTIONS(205),
    [anon_sym_to_string] = ACTIONS(205),
    [anon_sym_upper] = ACTIONS(205),
    [anon_sym_url_decode] = ACTIONS(205),
    [anon_sym_uuidv4] = ACTIONS(205),
    [anon_sym_len] = ACTIONS(205),
    [anon_sym_ends_with] = ACTIONS(205),
    [anon_sym_starts_with] = ACTIONS(205),
    [anon_sym_any] = ACTIONS(205),
    [anon_sym_all] = ACTIONS(205),
    [anon_sym_true] = ACTIONS(205),
    [anon_sym_false] = ACTIONS(205),
    [anon_sym_not] = ACTIONS(205),
    [anon_sym_BANG] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(205),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(205),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(207),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(205),
    [anon_sym_icmp_DOTtype] = ACTIONS(205),
    [anon_sym_icmp_DOTcode] = ACTIONS(205),
    [anon_sym_ip_DOThdr_len] = ACTIONS(205),
    [anon_sym_ip_DOTlen] = ACTIONS(205),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(205),
    [anon_sym_ip_DOTttl] = ACTIONS(205),
    [anon_sym_tcp_DOTflags] = ACTIONS(207),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(205),
    [anon_sym_tcp_DOTdstport] = ACTIONS(205),
    [anon_sym_udp_DOTdstport] = ACTIONS(205),
    [anon_sym_udp_DOTsrcport] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc] = ACTIONS(207),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(205),
    [anon_sym_ip_DOTdst] = ACTIONS(207),
    [anon_sym_http_DOTcookie] = ACTIONS(205),
    [anon_sym_http_DOThost] = ACTIONS(205),
    [anon_sym_http_DOTreferer] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(205),
    [anon_sym_http_DOTuser_agent] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(205),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(205),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(205),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(205),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(205),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(205),
    [anon_sym_icmp] = ACTIONS(207),
    [anon_sym_ip] = ACTIONS(207),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(205),
    [anon_sym_tcp] = ACTIONS(207),
    [anon_sym_udp] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(205),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(207),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(205),
    [anon_sym_ssl] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(205),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(205),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(205),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(205),
    [anon_sym_sip] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(205),
  },
  [59] = {
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
  [60] = {
    [ts_builtin_sym_end] = ACTIONS(209),
    [anon_sym_AMP_AMP] = ACTIONS(209),
    [anon_sym_and] = ACTIONS(209),
    [anon_sym_xor] = ACTIONS(209),
    [anon_sym_CARET_CARET] = ACTIONS(209),
    [anon_sym_or] = ACTIONS(209),
    [anon_sym_PIPE_PIPE] = ACTIONS(209),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(209),
    [anon_sym_LPAREN] = ACTIONS(209),
    [anon_sym_RPAREN] = ACTIONS(209),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(209),
    [anon_sym_icmp_DOTtype] = ACTIONS(209),
    [anon_sym_icmp_DOTcode] = ACTIONS(209),
    [anon_sym_ip_DOThdr_len] = ACTIONS(209),
    [anon_sym_ip_DOTlen] = ACTIONS(209),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(209),
    [anon_sym_ip_DOTttl] = ACTIONS(209),
    [anon_sym_tcp_DOTflags] = ACTIONS(211),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(209),
    [anon_sym_tcp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTsrcport] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc] = ACTIONS(211),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(209),
    [anon_sym_ip_DOTdst] = ACTIONS(211),
    [anon_sym_http_DOTcookie] = ACTIONS(209),
    [anon_sym_http_DOThost] = ACTIONS(209),
    [anon_sym_http_DOTreferer] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(211),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(209),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(209),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(209),
    [anon_sym_icmp] = ACTIONS(211),
    [anon_sym_ip] = ACTIONS(211),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(209),
    [anon_sym_tcp] = ACTIONS(211),
    [anon_sym_udp] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(209),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(211),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(211),
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
  [61] = {
    [ts_builtin_sym_end] = ACTIONS(213),
    [anon_sym_AMP_AMP] = ACTIONS(213),
    [anon_sym_and] = ACTIONS(213),
    [anon_sym_xor] = ACTIONS(213),
    [anon_sym_CARET_CARET] = ACTIONS(213),
    [anon_sym_or] = ACTIONS(213),
    [anon_sym_PIPE_PIPE] = ACTIONS(213),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(213),
    [anon_sym_LPAREN] = ACTIONS(213),
    [anon_sym_RPAREN] = ACTIONS(213),
    [anon_sym_lookup_json_string] = ACTIONS(213),
    [anon_sym_lower] = ACTIONS(213),
    [anon_sym_regex_replace] = ACTIONS(213),
    [anon_sym_remove_bytes] = ACTIONS(213),
    [anon_sym_to_string] = ACTIONS(213),
    [anon_sym_upper] = ACTIONS(213),
    [anon_sym_url_decode] = ACTIONS(213),
    [anon_sym_uuidv4] = ACTIONS(213),
    [anon_sym_len] = ACTIONS(213),
    [anon_sym_ends_with] = ACTIONS(213),
    [anon_sym_starts_with] = ACTIONS(213),
    [anon_sym_any] = ACTIONS(213),
    [anon_sym_all] = ACTIONS(213),
    [anon_sym_true] = ACTIONS(213),
    [anon_sym_false] = ACTIONS(213),
    [anon_sym_not] = ACTIONS(213),
    [anon_sym_BANG] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(213),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(213),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(213),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(213),
    [anon_sym_icmp_DOTtype] = ACTIONS(213),
    [anon_sym_icmp_DOTcode] = ACTIONS(213),
    [anon_sym_ip_DOThdr_len] = ACTIONS(213),
    [anon_sym_ip_DOTlen] = ACTIONS(213),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(213),
    [anon_sym_ip_DOTttl] = ACTIONS(213),
    [anon_sym_tcp_DOTflags] = ACTIONS(215),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(213),
    [anon_sym_tcp_DOTdstport] = ACTIONS(213),
    [anon_sym_udp_DOTdstport] = ACTIONS(213),
    [anon_sym_udp_DOTsrcport] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(213),
    [anon_sym_ip_DOTsrc] = ACTIONS(215),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(213),
    [anon_sym_ip_DOTdst] = ACTIONS(215),
    [anon_sym_http_DOTcookie] = ACTIONS(213),
    [anon_sym_http_DOThost] = ACTIONS(213),
    [anon_sym_http_DOTreferer] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(213),
    [anon_sym_http_DOTuser_agent] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(213),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(213),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(213),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(213),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(213),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(213),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(213),
    [anon_sym_icmp] = ACTIONS(215),
    [anon_sym_ip] = ACTIONS(215),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(213),
    [anon_sym_tcp] = ACTIONS(215),
    [anon_sym_udp] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(213),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(213),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(213),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(213),
    [anon_sym_ssl] = ACTIONS(213),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(213),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(213),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(213),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(213),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(213),
    [anon_sym_sip] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(213),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(213),
  },
  [62] = {
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
  [63] = {
    [ts_builtin_sym_end] = ACTIONS(217),
    [anon_sym_AMP_AMP] = ACTIONS(217),
    [anon_sym_and] = ACTIONS(217),
    [anon_sym_xor] = ACTIONS(217),
    [anon_sym_CARET_CARET] = ACTIONS(217),
    [anon_sym_or] = ACTIONS(217),
    [anon_sym_PIPE_PIPE] = ACTIONS(217),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(217),
    [anon_sym_LPAREN] = ACTIONS(217),
    [anon_sym_RPAREN] = ACTIONS(217),
    [anon_sym_lookup_json_string] = ACTIONS(217),
    [anon_sym_lower] = ACTIONS(217),
    [anon_sym_regex_replace] = ACTIONS(217),
    [anon_sym_remove_bytes] = ACTIONS(217),
    [anon_sym_to_string] = ACTIONS(217),
    [anon_sym_upper] = ACTIONS(217),
    [anon_sym_url_decode] = ACTIONS(217),
    [anon_sym_uuidv4] = ACTIONS(217),
    [anon_sym_len] = ACTIONS(217),
    [anon_sym_ends_with] = ACTIONS(217),
    [anon_sym_starts_with] = ACTIONS(217),
    [anon_sym_any] = ACTIONS(217),
    [anon_sym_all] = ACTIONS(217),
    [anon_sym_true] = ACTIONS(217),
    [anon_sym_false] = ACTIONS(217),
    [anon_sym_not] = ACTIONS(217),
    [anon_sym_BANG] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(217),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(217),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(219),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(217),
    [anon_sym_icmp_DOTtype] = ACTIONS(217),
    [anon_sym_icmp_DOTcode] = ACTIONS(217),
    [anon_sym_ip_DOThdr_len] = ACTIONS(217),
    [anon_sym_ip_DOTlen] = ACTIONS(217),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(217),
    [anon_sym_ip_DOTttl] = ACTIONS(217),
    [anon_sym_tcp_DOTflags] = ACTIONS(219),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(217),
    [anon_sym_tcp_DOTdstport] = ACTIONS(217),
    [anon_sym_udp_DOTdstport] = ACTIONS(217),
    [anon_sym_udp_DOTsrcport] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(217),
    [anon_sym_ip_DOTsrc] = ACTIONS(219),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(217),
    [anon_sym_ip_DOTdst] = ACTIONS(219),
    [anon_sym_http_DOTcookie] = ACTIONS(217),
    [anon_sym_http_DOThost] = ACTIONS(217),
    [anon_sym_http_DOTreferer] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(217),
    [anon_sym_http_DOTuser_agent] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(217),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(217),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(217),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(217),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(217),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(217),
    [anon_sym_icmp] = ACTIONS(219),
    [anon_sym_ip] = ACTIONS(219),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(217),
    [anon_sym_tcp] = ACTIONS(219),
    [anon_sym_udp] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(217),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(219),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(217),
    [anon_sym_ssl] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(217),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(217),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(217),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(217),
    [anon_sym_sip] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(217),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(217),
  },
  [64] = {
    [ts_builtin_sym_end] = ACTIONS(221),
    [anon_sym_AMP_AMP] = ACTIONS(221),
    [anon_sym_and] = ACTIONS(221),
    [anon_sym_xor] = ACTIONS(221),
    [anon_sym_CARET_CARET] = ACTIONS(221),
    [anon_sym_or] = ACTIONS(221),
    [anon_sym_PIPE_PIPE] = ACTIONS(221),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(221),
    [anon_sym_LPAREN] = ACTIONS(221),
    [anon_sym_RPAREN] = ACTIONS(221),
    [anon_sym_lookup_json_string] = ACTIONS(221),
    [anon_sym_lower] = ACTIONS(221),
    [anon_sym_regex_replace] = ACTIONS(221),
    [anon_sym_remove_bytes] = ACTIONS(221),
    [anon_sym_to_string] = ACTIONS(221),
    [anon_sym_upper] = ACTIONS(221),
    [anon_sym_url_decode] = ACTIONS(221),
    [anon_sym_uuidv4] = ACTIONS(221),
    [anon_sym_len] = ACTIONS(221),
    [anon_sym_ends_with] = ACTIONS(221),
    [anon_sym_starts_with] = ACTIONS(221),
    [anon_sym_any] = ACTIONS(221),
    [anon_sym_all] = ACTIONS(221),
    [anon_sym_true] = ACTIONS(221),
    [anon_sym_false] = ACTIONS(221),
    [anon_sym_not] = ACTIONS(221),
    [anon_sym_BANG] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(221),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(221),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(221),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(221),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(223),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(221),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(221),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(221),
    [anon_sym_icmp_DOTtype] = ACTIONS(221),
    [anon_sym_icmp_DOTcode] = ACTIONS(221),
    [anon_sym_ip_DOThdr_len] = ACTIONS(221),
    [anon_sym_ip_DOTlen] = ACTIONS(221),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(221),
    [anon_sym_ip_DOTttl] = ACTIONS(221),
    [anon_sym_tcp_DOTflags] = ACTIONS(223),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(221),
    [anon_sym_tcp_DOTdstport] = ACTIONS(221),
    [anon_sym_udp_DOTdstport] = ACTIONS(221),
    [anon_sym_udp_DOTsrcport] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(221),
    [anon_sym_ip_DOTsrc] = ACTIONS(223),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(221),
    [anon_sym_ip_DOTdst] = ACTIONS(223),
    [anon_sym_http_DOTcookie] = ACTIONS(221),
    [anon_sym_http_DOThost] = ACTIONS(221),
    [anon_sym_http_DOTreferer] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(221),
    [anon_sym_http_DOTuser_agent] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(221),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(221),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(221),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(221),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(221),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(221),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(221),
    [anon_sym_icmp] = ACTIONS(223),
    [anon_sym_ip] = ACTIONS(223),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(221),
    [anon_sym_tcp] = ACTIONS(223),
    [anon_sym_udp] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(221),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(223),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(221),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(221),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(221),
    [anon_sym_ssl] = ACTIONS(221),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(221),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(221),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(221),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(221),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(221),
    [anon_sym_sip] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(221),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(221),
  },
  [65] = {
    [ts_builtin_sym_end] = ACTIONS(225),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(173),
    [anon_sym_xor] = ACTIONS(175),
    [anon_sym_CARET_CARET] = ACTIONS(177),
    [anon_sym_or] = ACTIONS(227),
    [anon_sym_PIPE_PIPE] = ACTIONS(229),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(225),
    [anon_sym_LPAREN] = ACTIONS(225),
    [anon_sym_lookup_json_string] = ACTIONS(225),
    [anon_sym_lower] = ACTIONS(225),
    [anon_sym_regex_replace] = ACTIONS(225),
    [anon_sym_remove_bytes] = ACTIONS(225),
    [anon_sym_to_string] = ACTIONS(225),
    [anon_sym_upper] = ACTIONS(225),
    [anon_sym_url_decode] = ACTIONS(225),
    [anon_sym_uuidv4] = ACTIONS(225),
    [anon_sym_len] = ACTIONS(225),
    [anon_sym_ends_with] = ACTIONS(225),
    [anon_sym_starts_with] = ACTIONS(225),
    [anon_sym_any] = ACTIONS(225),
    [anon_sym_all] = ACTIONS(225),
    [anon_sym_true] = ACTIONS(225),
    [anon_sym_false] = ACTIONS(225),
    [anon_sym_not] = ACTIONS(225),
    [anon_sym_BANG] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(225),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(225),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(225),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(225),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(231),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(225),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(225),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(225),
    [anon_sym_icmp_DOTtype] = ACTIONS(225),
    [anon_sym_icmp_DOTcode] = ACTIONS(225),
    [anon_sym_ip_DOThdr_len] = ACTIONS(225),
    [anon_sym_ip_DOTlen] = ACTIONS(225),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(225),
    [anon_sym_ip_DOTttl] = ACTIONS(225),
    [anon_sym_tcp_DOTflags] = ACTIONS(231),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(225),
    [anon_sym_tcp_DOTdstport] = ACTIONS(225),
    [anon_sym_udp_DOTdstport] = ACTIONS(225),
    [anon_sym_udp_DOTsrcport] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(225),
    [anon_sym_ip_DOTsrc] = ACTIONS(231),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(225),
    [anon_sym_ip_DOTdst] = ACTIONS(231),
    [anon_sym_http_DOTcookie] = ACTIONS(225),
    [anon_sym_http_DOThost] = ACTIONS(225),
    [anon_sym_http_DOTreferer] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(225),
    [anon_sym_http_DOTuser_agent] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(225),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(225),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(225),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(225),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(225),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(225),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(225),
    [anon_sym_icmp] = ACTIONS(231),
    [anon_sym_ip] = ACTIONS(231),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(225),
    [anon_sym_tcp] = ACTIONS(231),
    [anon_sym_udp] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(225),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(231),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(225),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(225),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(225),
    [anon_sym_ssl] = ACTIONS(225),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(225),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(225),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(225),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(225),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(225),
    [anon_sym_sip] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(225),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(225),
  },
  [66] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(233),
    [anon_sym_LPAREN] = ACTIONS(233),
    [anon_sym_lookup_json_string] = ACTIONS(233),
    [anon_sym_lower] = ACTIONS(233),
    [anon_sym_regex_replace] = ACTIONS(233),
    [anon_sym_remove_bytes] = ACTIONS(233),
    [anon_sym_to_string] = ACTIONS(233),
    [anon_sym_upper] = ACTIONS(233),
    [anon_sym_url_decode] = ACTIONS(233),
    [anon_sym_uuidv4] = ACTIONS(233),
    [anon_sym_len] = ACTIONS(233),
    [anon_sym_ends_with] = ACTIONS(233),
    [anon_sym_starts_with] = ACTIONS(233),
    [anon_sym_any] = ACTIONS(233),
    [anon_sym_all] = ACTIONS(233),
    [anon_sym_true] = ACTIONS(233),
    [anon_sym_false] = ACTIONS(233),
    [anon_sym_not] = ACTIONS(233),
    [anon_sym_BANG] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(233),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(233),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(233),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(233),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(235),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(233),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(233),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(233),
    [anon_sym_icmp_DOTtype] = ACTIONS(233),
    [anon_sym_icmp_DOTcode] = ACTIONS(233),
    [anon_sym_ip_DOThdr_len] = ACTIONS(233),
    [anon_sym_ip_DOTlen] = ACTIONS(233),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(233),
    [anon_sym_ip_DOTttl] = ACTIONS(233),
    [anon_sym_tcp_DOTflags] = ACTIONS(235),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(233),
    [anon_sym_tcp_DOTdstport] = ACTIONS(233),
    [anon_sym_udp_DOTdstport] = ACTIONS(233),
    [anon_sym_udp_DOTsrcport] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(233),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(233),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(233),
    [anon_sym_ip_DOTsrc] = ACTIONS(235),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(233),
    [anon_sym_ip_DOTdst] = ACTIONS(235),
    [anon_sym_http_DOTcookie] = ACTIONS(233),
    [anon_sym_http_DOThost] = ACTIONS(233),
    [anon_sym_http_DOTreferer] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(233),
    [anon_sym_http_DOTuser_agent] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(233),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(233),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(233),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(233),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(233),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(233),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(233),
    [anon_sym_icmp] = ACTIONS(235),
    [anon_sym_ip] = ACTIONS(235),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(233),
    [anon_sym_tcp] = ACTIONS(235),
    [anon_sym_udp] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(233),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(235),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(233),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(233),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(233),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(233),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(233),
    [anon_sym_ssl] = ACTIONS(233),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(233),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(233),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(233),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(233),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(233),
    [anon_sym_sip] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(233),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(233),
  },
  [67] = {
    [anon_sym_in] = ACTIONS(237),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(237),
    [anon_sym_ne] = ACTIONS(237),
    [anon_sym_lt] = ACTIONS(237),
    [anon_sym_le] = ACTIONS(237),
    [anon_sym_gt] = ACTIONS(237),
    [anon_sym_ge] = ACTIONS(237),
    [anon_sym_EQ_EQ] = ACTIONS(237),
    [anon_sym_BANG_EQ] = ACTIONS(237),
    [anon_sym_LT] = ACTIONS(239),
    [anon_sym_LT_EQ] = ACTIONS(237),
    [anon_sym_GT] = ACTIONS(239),
    [anon_sym_GT_EQ] = ACTIONS(237),
    [anon_sym_contains] = ACTIONS(237),
    [anon_sym_matches] = ACTIONS(237),
    [anon_sym_TILDE] = ACTIONS(237),
    [anon_sym_concat] = ACTIONS(237),
    [anon_sym_COMMA] = ACTIONS(237),
    [anon_sym_RPAREN] = ACTIONS(237),
    [anon_sym_lookup_json_string] = ACTIONS(237),
    [anon_sym_lower] = ACTIONS(237),
    [anon_sym_regex_replace] = ACTIONS(237),
    [anon_sym_remove_bytes] = ACTIONS(237),
    [anon_sym_to_string] = ACTIONS(237),
    [anon_sym_upper] = ACTIONS(237),
    [anon_sym_url_decode] = ACTIONS(237),
    [anon_sym_uuidv4] = ACTIONS(237),
    [sym_number] = ACTIONS(237),
    [sym_string] = ACTIONS(237),
    [anon_sym_http_DOTcookie] = ACTIONS(237),
    [anon_sym_http_DOThost] = ACTIONS(237),
    [anon_sym_http_DOTreferer] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(237),
    [anon_sym_http_DOTuser_agent] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(237),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(237),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(237),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(237),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(237),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(237),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(237),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(237),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(237),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(237),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(237),
    [anon_sym_icmp] = ACTIONS(237),
    [anon_sym_ip] = ACTIONS(239),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(237),
    [anon_sym_tcp] = ACTIONS(237),
    [anon_sym_udp] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(237),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(239),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(237),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(237),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(237),
  },
  [68] = {
    [anon_sym_in] = ACTIONS(241),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(241),
    [anon_sym_ne] = ACTIONS(241),
    [anon_sym_lt] = ACTIONS(241),
    [anon_sym_le] = ACTIONS(241),
    [anon_sym_gt] = ACTIONS(241),
    [anon_sym_ge] = ACTIONS(241),
    [anon_sym_EQ_EQ] = ACTIONS(241),
    [anon_sym_BANG_EQ] = ACTIONS(241),
    [anon_sym_LT] = ACTIONS(243),
    [anon_sym_LT_EQ] = ACTIONS(241),
    [anon_sym_GT] = ACTIONS(243),
    [anon_sym_GT_EQ] = ACTIONS(241),
    [anon_sym_contains] = ACTIONS(241),
    [anon_sym_matches] = ACTIONS(241),
    [anon_sym_TILDE] = ACTIONS(241),
    [anon_sym_concat] = ACTIONS(241),
    [anon_sym_COMMA] = ACTIONS(241),
    [anon_sym_RPAREN] = ACTIONS(241),
    [anon_sym_lookup_json_string] = ACTIONS(241),
    [anon_sym_lower] = ACTIONS(241),
    [anon_sym_regex_replace] = ACTIONS(241),
    [anon_sym_remove_bytes] = ACTIONS(241),
    [anon_sym_to_string] = ACTIONS(241),
    [anon_sym_upper] = ACTIONS(241),
    [anon_sym_url_decode] = ACTIONS(241),
    [anon_sym_uuidv4] = ACTIONS(241),
    [sym_number] = ACTIONS(241),
    [sym_string] = ACTIONS(241),
    [anon_sym_http_DOTcookie] = ACTIONS(241),
    [anon_sym_http_DOThost] = ACTIONS(241),
    [anon_sym_http_DOTreferer] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(241),
    [anon_sym_http_DOTuser_agent] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(241),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(241),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(241),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(241),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(241),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(241),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(241),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(241),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(241),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(241),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(241),
    [anon_sym_icmp] = ACTIONS(241),
    [anon_sym_ip] = ACTIONS(243),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(241),
    [anon_sym_tcp] = ACTIONS(241),
    [anon_sym_udp] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(241),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(243),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(241),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(241),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(241),
  },
  [69] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(69),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(245),
    [anon_sym_RPAREN] = ACTIONS(248),
    [anon_sym_lookup_json_string] = ACTIONS(250),
    [anon_sym_lower] = ACTIONS(253),
    [anon_sym_regex_replace] = ACTIONS(256),
    [anon_sym_remove_bytes] = ACTIONS(259),
    [anon_sym_to_string] = ACTIONS(262),
    [anon_sym_upper] = ACTIONS(253),
    [anon_sym_url_decode] = ACTIONS(253),
    [anon_sym_uuidv4] = ACTIONS(265),
    [sym_string] = ACTIONS(268),
    [anon_sym_http_DOTcookie] = ACTIONS(271),
    [anon_sym_http_DOThost] = ACTIONS(271),
    [anon_sym_http_DOTreferer] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(274),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(271),
    [anon_sym_http_DOTuser_agent] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(271),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(271),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(271),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(271),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(271),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(271),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(271),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(274),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(271),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(271),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(271),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(271),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(271),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(271),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(271),
    [anon_sym_icmp] = ACTIONS(271),
    [anon_sym_ip] = ACTIONS(274),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(271),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(271),
    [anon_sym_tcp] = ACTIONS(271),
    [anon_sym_udp] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(271),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(271),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(277),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(280),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(280),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(280),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(280),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(280),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(283),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(283),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(283),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(283),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(283),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(283),
  },
  [70] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(69),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_RPAREN] = ACTIONS(288),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [71] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(69),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_RPAREN] = ACTIONS(304),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [72] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(69),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_RPAREN] = ACTIONS(306),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [73] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(69),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_RPAREN] = ACTIONS(308),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [74] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(285),
    [sym__stringlike_field] = STATE(286),
    [sym_string_field] = STATE(286),
    [sym_bytes_field] = STATE(287),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [75] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(182),
    [sym__stringlike_field] = STATE(180),
    [sym_string_field] = STATE(180),
    [sym_bytes_field] = STATE(179),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [76] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(70),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [77] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(73),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [78] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(72),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [79] = {
    [sym_string_array] = STATE(268),
    [sym__stringlike_field] = STATE(87),
    [sym_string_field] = STATE(87),
    [sym_map_string_array_field] = STATE(267),
    [sym_array_string_field] = STATE(262),
    [aux_sym_string_func_repeat1] = STATE(71),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(286),
    [anon_sym_lookup_json_string] = ACTIONS(290),
    [anon_sym_lower] = ACTIONS(292),
    [anon_sym_regex_replace] = ACTIONS(294),
    [anon_sym_remove_bytes] = ACTIONS(296),
    [anon_sym_to_string] = ACTIONS(298),
    [anon_sym_upper] = ACTIONS(292),
    [anon_sym_url_decode] = ACTIONS(292),
    [anon_sym_uuidv4] = ACTIONS(300),
    [sym_string] = ACTIONS(302),
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
  [80] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(189),
    [sym__stringlike_field] = STATE(188),
    [sym_string_field] = STATE(188),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
    [sym_string] = ACTIONS(328),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [81] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(186),
    [sym__stringlike_field] = STATE(185),
    [sym_string_field] = STATE(185),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [82] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(288),
    [sym__stringlike_field] = STATE(197),
    [sym_string_field] = STATE(197),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [83] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(184),
    [sym__stringlike_field] = STATE(183),
    [sym_string_field] = STATE(183),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [84] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(283),
    [sym__stringlike_field] = STATE(284),
    [sym_string_field] = STATE(284),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [85] = {
    [sym_string_array] = STATE(176),
    [sym__string_array_expansion] = STATE(142),
    [sym__stringlike_field] = STATE(151),
    [sym_string_field] = STATE(151),
    [sym_map_string_array_field] = STATE(187),
    [sym_array_string_field] = STATE(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(310),
    [anon_sym_lookup_json_string] = ACTIONS(312),
    [anon_sym_lower] = ACTIONS(314),
    [anon_sym_regex_replace] = ACTIONS(316),
    [anon_sym_remove_bytes] = ACTIONS(318),
    [anon_sym_to_string] = ACTIONS(320),
    [anon_sym_upper] = ACTIONS(314),
    [anon_sym_url_decode] = ACTIONS(314),
    [anon_sym_uuidv4] = ACTIONS(322),
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
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(326),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(326),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(326),
  },
  [86] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(330),
    [anon_sym_COMMA] = ACTIONS(332),
    [anon_sym_RPAREN] = ACTIONS(330),
    [anon_sym_lookup_json_string] = ACTIONS(330),
    [anon_sym_lower] = ACTIONS(330),
    [anon_sym_regex_replace] = ACTIONS(330),
    [anon_sym_remove_bytes] = ACTIONS(330),
    [anon_sym_to_string] = ACTIONS(330),
    [anon_sym_upper] = ACTIONS(330),
    [anon_sym_url_decode] = ACTIONS(330),
    [anon_sym_uuidv4] = ACTIONS(330),
    [sym_string] = ACTIONS(330),
    [anon_sym_http_DOTcookie] = ACTIONS(330),
    [anon_sym_http_DOThost] = ACTIONS(330),
    [anon_sym_http_DOTreferer] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(334),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(330),
    [anon_sym_http_DOTuser_agent] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(330),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(330),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(330),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(330),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(330),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(334),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(330),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(330),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(330),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(330),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(330),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(330),
    [anon_sym_icmp] = ACTIONS(330),
    [anon_sym_ip] = ACTIONS(334),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(330),
    [anon_sym_tcp] = ACTIONS(330),
    [anon_sym_udp] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(330),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(334),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(334),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(334),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(334),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(334),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(330),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(330),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(330),
  },
  [87] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(336),
    [anon_sym_COMMA] = ACTIONS(338),
    [anon_sym_RPAREN] = ACTIONS(336),
    [anon_sym_lookup_json_string] = ACTIONS(336),
    [anon_sym_lower] = ACTIONS(336),
    [anon_sym_regex_replace] = ACTIONS(336),
    [anon_sym_remove_bytes] = ACTIONS(336),
    [anon_sym_to_string] = ACTIONS(336),
    [anon_sym_upper] = ACTIONS(336),
    [anon_sym_url_decode] = ACTIONS(336),
    [anon_sym_uuidv4] = ACTIONS(336),
    [sym_string] = ACTIONS(336),
    [anon_sym_http_DOTcookie] = ACTIONS(336),
    [anon_sym_http_DOThost] = ACTIONS(336),
    [anon_sym_http_DOTreferer] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(340),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(336),
    [anon_sym_http_DOTuser_agent] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(336),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(336),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(336),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(336),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(336),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(336),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(336),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(340),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(336),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(336),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(336),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(336),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(336),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(336),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(336),
    [anon_sym_icmp] = ACTIONS(336),
    [anon_sym_ip] = ACTIONS(340),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(336),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(336),
    [anon_sym_tcp] = ACTIONS(336),
    [anon_sym_udp] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(336),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(340),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(340),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(340),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(340),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(340),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(336),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(336),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(336),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(336),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(336),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(336),
  },
  [88] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(342),
    [anon_sym_RPAREN] = ACTIONS(342),
    [anon_sym_lookup_json_string] = ACTIONS(342),
    [anon_sym_lower] = ACTIONS(342),
    [anon_sym_regex_replace] = ACTIONS(342),
    [anon_sym_remove_bytes] = ACTIONS(342),
    [anon_sym_to_string] = ACTIONS(342),
    [anon_sym_upper] = ACTIONS(342),
    [anon_sym_url_decode] = ACTIONS(342),
    [anon_sym_uuidv4] = ACTIONS(342),
    [sym_string] = ACTIONS(342),
    [anon_sym_http_DOTcookie] = ACTIONS(342),
    [anon_sym_http_DOThost] = ACTIONS(342),
    [anon_sym_http_DOTreferer] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(344),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(342),
    [anon_sym_http_DOTuser_agent] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(342),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(342),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(342),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(342),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(342),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(342),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(342),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(344),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(342),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(342),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(342),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(342),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(342),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(342),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(342),
    [anon_sym_icmp] = ACTIONS(342),
    [anon_sym_ip] = ACTIONS(344),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(342),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(342),
    [anon_sym_tcp] = ACTIONS(342),
    [anon_sym_udp] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(342),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(344),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(344),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(344),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(344),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(344),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(342),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(342),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(342),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(342),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(342),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(342),
  },
  [89] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(346),
    [anon_sym_RPAREN] = ACTIONS(346),
    [anon_sym_lookup_json_string] = ACTIONS(346),
    [anon_sym_lower] = ACTIONS(346),
    [anon_sym_regex_replace] = ACTIONS(346),
    [anon_sym_remove_bytes] = ACTIONS(346),
    [anon_sym_to_string] = ACTIONS(346),
    [anon_sym_upper] = ACTIONS(346),
    [anon_sym_url_decode] = ACTIONS(346),
    [anon_sym_uuidv4] = ACTIONS(346),
    [sym_string] = ACTIONS(346),
    [anon_sym_http_DOTcookie] = ACTIONS(346),
    [anon_sym_http_DOThost] = ACTIONS(346),
    [anon_sym_http_DOTreferer] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(348),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(346),
    [anon_sym_http_DOTuser_agent] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(346),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(346),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(346),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(346),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(346),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(346),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(346),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(348),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(346),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(346),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(346),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(346),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(346),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(346),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(346),
    [anon_sym_icmp] = ACTIONS(346),
    [anon_sym_ip] = ACTIONS(348),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(346),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(346),
    [anon_sym_tcp] = ACTIONS(346),
    [anon_sym_udp] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(346),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(348),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(348),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(348),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(348),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(348),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(346),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(346),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(346),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(346),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(346),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(346),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 1,
      anon_sym_len,
    ACTIONS(354), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(166), 1,
      sym_array_number_field,
    STATE(169), 1,
      sym_bool_array,
    STATE(170), 1,
      sym_number_array,
    STATE(282), 1,
      sym_ip_field,
    ACTIONS(35), 2,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_tcp_DOTflags,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(280), 2,
      sym__boollike_field,
      sym_bool_field,
    STATE(281), 2,
      sym__numberlike_field,
      sym_number_field,
    ACTIONS(39), 3,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
      anon_sym_ip_DOTdst,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    ACTIONS(350), 1,
      anon_sym_len,
    ACTIONS(354), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(166), 1,
      sym_array_number_field,
    STATE(167), 1,
      sym_array_string_field,
    STATE(235), 1,
      sym_number_array,
    STATE(290), 1,
      sym_string_array,
    STATE(291), 1,
      sym_bool_array,
    STATE(315), 1,
      sym_map_string_array_field,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(283), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(186), 1,
      sym__string_array_expansion,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(182), 1,
      sym__string_array_expansion,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(184), 1,
      sym__string_array_expansion,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(320), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(294), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(146), 1,
      sym__string_array_expansion,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(318), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(142), 1,
      sym__string_array_expansion,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(292), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(319), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(189), 1,
      sym__string_array_expansion,
    STATE(225), 1,
      sym_string_array,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(293), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
    ACTIONS(310), 1,
      anon_sym_concat,
    ACTIONS(312), 1,
      anon_sym_lookup_json_string,
    ACTIONS(316), 1,
      anon_sym_regex_replace,
    ACTIONS(318), 1,
      anon_sym_remove_bytes,
    ACTIONS(320), 1,
      anon_sym_to_string,
    ACTIONS(322), 1,
      anon_sym_uuidv4,
    STATE(167), 1,
      sym_array_string_field,
    STATE(187), 1,
      sym_map_string_array_field,
    STATE(225), 1,
      sym_string_array,
    STATE(327), 1,
      sym__string_array_expansion,
    ACTIONS(314), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(326), 11,
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
  [1033] = 3,
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
  [1057] = 3,
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
  [1081] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(364), 1,
      anon_sym_in,
    ACTIONS(368), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(366), 13,
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
  [1107] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(372), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(370), 14,
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
  [1131] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(374), 1,
      anon_sym_in,
    ACTIONS(376), 1,
      anon_sym_eq,
    ACTIONS(378), 1,
      anon_sym_ne,
    ACTIONS(380), 1,
      anon_sym_lt,
    ACTIONS(382), 1,
      anon_sym_le,
    ACTIONS(384), 1,
      anon_sym_gt,
    ACTIONS(386), 1,
      anon_sym_ge,
    ACTIONS(388), 1,
      anon_sym_EQ_EQ,
    ACTIONS(390), 1,
      anon_sym_BANG_EQ,
    ACTIONS(392), 1,
      anon_sym_LT,
    ACTIONS(394), 1,
      anon_sym_LT_EQ,
    ACTIONS(396), 1,
      anon_sym_GT,
    ACTIONS(398), 1,
      anon_sym_GT_EQ,
    ACTIONS(400), 1,
      anon_sym_contains,
    ACTIONS(402), 1,
      anon_sym_matches,
    ACTIONS(404), 1,
      anon_sym_TILDE,
  [1183] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(408), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(406), 14,
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
  [1207] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(412), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(410), 14,
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
  [1231] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(416), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(414), 14,
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
  [1255] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(420), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(418), 14,
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
  [1279] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(424), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(422), 14,
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
  [1303] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(428), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(426), 14,
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
  [1327] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(430), 14,
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
  [1351] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(430), 14,
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
  [1375] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(430), 14,
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
  [1399] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(436), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(434), 12,
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
  [1421] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(440), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(438), 12,
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
  [1443] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(444), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(442), 11,
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
  [1464] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(446), 1,
      anon_sym_in,
    ACTIONS(450), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(448), 10,
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
  [1487] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(452), 11,
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
  [1508] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      anon_sym_in,
    ACTIONS(458), 1,
      anon_sym_eq,
    ACTIONS(460), 1,
      anon_sym_ne,
    ACTIONS(462), 1,
      anon_sym_lt,
    ACTIONS(464), 1,
      anon_sym_le,
    ACTIONS(466), 1,
      anon_sym_gt,
    ACTIONS(468), 1,
      anon_sym_ge,
    ACTIONS(470), 1,
      anon_sym_EQ_EQ,
    ACTIONS(472), 1,
      anon_sym_BANG_EQ,
    ACTIONS(474), 1,
      anon_sym_LT,
    ACTIONS(476), 1,
      anon_sym_LT_EQ,
    ACTIONS(478), 1,
      anon_sym_GT,
    ACTIONS(480), 1,
      anon_sym_GT_EQ,
  [1551] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(482), 11,
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
  [1572] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 1,
      anon_sym_len,
    ACTIONS(354), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(166), 1,
      sym_array_number_field,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(226), 2,
      sym_number_array,
      sym_bool_array,
  [1593] = 8,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(171), 1,
      anon_sym_AMP_AMP,
    ACTIONS(173), 1,
      anon_sym_and,
    ACTIONS(175), 1,
      anon_sym_xor,
    ACTIONS(177), 1,
      anon_sym_CARET_CARET,
    ACTIONS(227), 1,
      anon_sym_or,
    ACTIONS(229), 1,
      anon_sym_PIPE_PIPE,
    ACTIONS(486), 1,
      anon_sym_RPAREN,
  [1618] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 1,
      anon_sym_len,
    ACTIONS(354), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(166), 1,
      sym_array_number_field,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(300), 2,
      sym_number_array,
      sym_bool_array,
  [1639] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [1651] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(490), 1,
      anon_sym_in,
    ACTIONS(492), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [1664] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_RBRACE,
    ACTIONS(496), 1,
      sym_ipv4,
    STATE(132), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1679] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(499), 1,
      anon_sym_RBRACE,
    ACTIONS(501), 1,
      sym_ipv4,
    STATE(132), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1694] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(503), 1,
      anon_sym_RPAREN,
    STATE(136), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1708] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(507), 1,
      anon_sym_RPAREN,
    STATE(136), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1722] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(509), 1,
      anon_sym_RPAREN,
    STATE(136), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(511), 2,
      sym_number,
      sym_string,
  [1736] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_COMMA,
    ACTIONS(516), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1748] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      anon_sym_RPAREN,
    STATE(136), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1762] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(501), 1,
      sym_ipv4,
    STATE(133), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1774] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1784] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(522), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1794] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(135), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1805] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(509), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1814] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(501), 1,
      sym_ipv4,
    STATE(58), 2,
      sym__ip,
      sym_ip_range,
  [1825] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_RBRACE,
    ACTIONS(526), 1,
      sym_number,
    STATE(145), 1,
      aux_sym_number_set_repeat1,
  [1838] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(138), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1849] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(529), 1,
      anon_sym_RBRACE,
    ACTIONS(531), 1,
      sym_number,
    STATE(145), 1,
      aux_sym_number_set_repeat1,
  [1862] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(533), 1,
      anon_sym_RBRACE,
    ACTIONS(535), 1,
      sym_string,
    STATE(148), 1,
      aux_sym_string_set_repeat1,
  [1875] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      anon_sym_RBRACE,
    ACTIONS(540), 1,
      sym_string,
    STATE(148), 1,
      aux_sym_string_set_repeat1,
  [1888] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LBRACE,
    ACTIONS(544), 1,
      sym_ip_list,
    STATE(50), 1,
      sym_ip_set,
  [1901] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(134), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(505), 2,
      sym_number,
      sym_string,
  [1912] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      anon_sym_LBRACE,
    STATE(271), 1,
      sym_number_set,
  [1922] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [1930] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(550), 1,
      sym_string,
    STATE(149), 1,
      aux_sym_string_set_repeat1,
  [1940] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(554), 1,
      anon_sym_LBRACK,
  [1950] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(556), 1,
      sym_number,
    STATE(147), 1,
      aux_sym_number_set_repeat1,
  [1960] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(560), 1,
      anon_sym_LBRACK,
  [1970] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(564), 1,
      anon_sym_LBRACK,
  [1980] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(568), 1,
      anon_sym_LBRACK,
  [1990] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(572), 1,
      anon_sym_LBRACK,
  [2000] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(576), 1,
      anon_sym_LBRACK,
  [2010] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(580), 1,
      anon_sym_LBRACK,
  [2020] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(584), 1,
      anon_sym_LBRACK,
  [2030] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(588), 1,
      anon_sym_LBRACK,
  [2040] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(592), 1,
      anon_sym_LBRACK,
  [2050] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(596), 1,
      anon_sym_LBRACK,
  [2060] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(600), 1,
      anon_sym_LBRACK,
  [2070] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(604), 1,
      anon_sym_LBRACK,
  [2080] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(608), 1,
      anon_sym_LBRACK,
  [2090] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(610), 1,
      anon_sym_LBRACK,
  [2100] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(614), 1,
      anon_sym_LBRACK,
  [2110] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      anon_sym_LBRACE,
    STATE(26), 1,
      sym_number_set,
  [2120] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      anon_sym_LBRACE,
    STATE(271), 1,
      sym_string_set,
  [2130] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      anon_sym_LBRACE,
    STATE(62), 1,
      sym_string_set,
  [2140] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      sym_string,
    ACTIONS(620), 1,
      anon_sym_STAR,
  [2150] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(624), 1,
      anon_sym_LBRACK,
  [2160] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(626), 1,
      sym_string,
  [2167] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(628), 1,
      sym_number,
  [2174] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(630), 1,
      anon_sym_COMMA,
  [2181] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(632), 1,
      anon_sym_COMMA,
  [2188] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(634), 1,
      anon_sym_RBRACK,
  [2195] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(636), 1,
      anon_sym_COMMA,
  [2202] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(638), 1,
      anon_sym_COMMA,
  [2209] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(640), 1,
      anon_sym_COMMA,
  [2216] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(642), 1,
      anon_sym_RPAREN,
  [2223] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(644), 1,
      anon_sym_RPAREN,
  [2230] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(646), 1,
      anon_sym_LBRACK,
  [2237] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      anon_sym_COMMA,
  [2244] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(650), 1,
      anon_sym_COMMA,
  [2251] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(652), 1,
      anon_sym_COMMA,
  [2258] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(654), 1,
      anon_sym_LPAREN,
  [2265] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(656), 1,
      anon_sym_LPAREN,
  [2272] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(658), 1,
      anon_sym_LPAREN,
  [2279] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_LBRACK,
  [2286] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(660), 1,
      anon_sym_LPAREN,
  [2293] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(662), 1,
      sym_string,
  [2300] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(664), 1,
      anon_sym_COMMA,
  [2307] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(666), 1,
      sym_string,
  [2314] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(668), 1,
      sym_string,
  [2321] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(670), 1,
      sym_string,
  [2328] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(672), 1,
      anon_sym_LPAREN,
  [2335] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(674), 1,
      anon_sym_LPAREN,
  [2342] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(676), 1,
      anon_sym_RPAREN,
  [2349] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(678), 1,
      anon_sym_LPAREN,
  [2356] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(680), 1,
      sym_string,
  [2363] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(682), 1,
      sym_number,
  [2370] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_LBRACK,
  [2377] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(684), 1,
      sym_number,
  [2384] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_LBRACK,
  [2391] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(686), 1,
      sym_number,
  [2398] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(688), 1,
      sym_string,
  [2405] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(690), 1,
      sym_string,
  [2412] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(692), 1,
      sym_string,
  [2419] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(694), 1,
      sym_string,
  [2426] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(696), 1,
      anon_sym_RPAREN,
  [2433] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(698), 1,
      sym_string,
  [2440] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(700), 1,
      sym_string,
  [2447] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(702), 1,
      sym_string,
  [2454] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(704), 1,
      sym_string,
  [2461] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(706), 1,
      sym_string,
  [2468] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(708), 1,
      sym_string,
  [2475] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(710), 1,
      sym_string,
  [2482] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(712), 1,
      aux_sym_ip_range_token1,
  [2489] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      anon_sym_LBRACK,
  [2496] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2503] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(714), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2510] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(716), 1,
      sym_string,
  [2517] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(718), 1,
      sym_string,
  [2524] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(720), 1,
      sym_string,
  [2531] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(722), 1,
      sym_string,
  [2538] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(724), 1,
      sym_string,
  [2545] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(726), 1,
      anon_sym_RBRACK,
  [2552] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(728), 1,
      sym_string,
  [2559] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      anon_sym_LBRACK,
  [2566] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(730), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2573] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(732), 1,
      sym_number,
  [2580] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(734), 1,
      anon_sym_COMMA,
  [2587] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(736), 1,
      anon_sym_COMMA,
  [2594] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(738), 1,
      anon_sym_RPAREN,
  [2601] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(740), 1,
      anon_sym_RPAREN,
  [2608] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(742), 1,
      anon_sym_RPAREN,
  [2615] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_LBRACK,
  [2622] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(744), 1,
      anon_sym_RPAREN,
  [2629] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(746), 1,
      anon_sym_RPAREN,
  [2636] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(748), 1,
      sym_number,
  [2643] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(750), 1,
      sym_number,
  [2650] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(752), 1,
      sym_number,
  [2657] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(754), 1,
      anon_sym_LPAREN,
  [2664] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(750), 1,
      sym_string,
  [2671] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(756), 1,
      sym_number,
  [2678] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(758), 1,
      sym_number,
  [2685] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(760), 1,
      sym_number,
  [2692] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(762), 1,
      sym_number,
  [2699] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(764), 1,
      anon_sym_LPAREN,
  [2706] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(766), 1,
      sym_number,
  [2713] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(768), 1,
      sym_number,
  [2720] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(770), 1,
      sym_number,
  [2727] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(772), 1,
      sym_number,
  [2734] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(774), 1,
      anon_sym_RBRACK,
  [2741] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_LBRACK,
  [2748] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LBRACK,
  [2755] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_LBRACK,
  [2762] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(776), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2769] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(778), 1,
      sym_string,
  [2776] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(780), 1,
      sym_string,
  [2783] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_LBRACK,
  [2790] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(782), 1,
      anon_sym_LBRACK,
  [2797] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(784), 1,
      anon_sym_LBRACK,
  [2804] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_LBRACK,
  [2811] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(786), 1,
      anon_sym_LBRACK,
  [2818] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(788), 1,
      anon_sym_RPAREN,
  [2825] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(790), 1,
      anon_sym_LBRACK,
  [2832] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(792), 1,
      anon_sym_RPAREN,
  [2839] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(794), 1,
      anon_sym_RPAREN,
  [2846] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(796), 1,
      ts_builtin_sym_end,
  [2853] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      anon_sym_LBRACK,
  [2860] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      anon_sym_LBRACK,
  [2867] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(798), 1,
      anon_sym_RBRACK,
  [2874] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(800), 1,
      anon_sym_RBRACK,
  [2881] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(802), 1,
      anon_sym_RPAREN,
  [2888] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(804), 1,
      anon_sym_RPAREN,
  [2895] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(806), 1,
      anon_sym_RPAREN,
  [2902] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(808), 1,
      anon_sym_RPAREN,
  [2909] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(810), 1,
      anon_sym_RPAREN,
  [2916] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(812), 1,
      anon_sym_RPAREN,
  [2923] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(814), 1,
      anon_sym_RPAREN,
  [2930] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(816), 1,
      anon_sym_RPAREN,
  [2937] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(818), 1,
      anon_sym_COMMA,
  [2944] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(820), 1,
      anon_sym_LPAREN,
  [2951] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(822), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2958] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(824), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2965] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(826), 1,
      anon_sym_RPAREN,
  [2972] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(828), 1,
      anon_sym_RPAREN,
  [2979] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(830), 1,
      anon_sym_RPAREN,
  [2986] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(832), 1,
      anon_sym_RBRACK,
  [2993] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_LBRACK,
  [3000] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(834), 1,
      anon_sym_LBRACK,
  [3007] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(836), 1,
      anon_sym_LPAREN,
  [3014] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(838), 1,
      anon_sym_RPAREN,
  [3021] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3028] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(840), 1,
      anon_sym_LPAREN,
  [3035] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(842), 1,
      anon_sym_RPAREN,
  [3042] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(844), 1,
      anon_sym_RPAREN,
  [3049] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(846), 1,
      anon_sym_RPAREN,
  [3056] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      sym_string,
  [3063] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(848), 1,
      anon_sym_LPAREN,
  [3070] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(850), 1,
      anon_sym_LPAREN,
  [3077] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(852), 1,
      anon_sym_LPAREN,
  [3084] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(854), 1,
      anon_sym_LPAREN,
  [3091] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(856), 1,
      anon_sym_LPAREN,
  [3098] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(858), 1,
      anon_sym_LPAREN,
  [3105] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(860), 1,
      sym_string,
  [3112] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(862), 1,
      sym_string,
  [3119] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(864), 1,
      sym_string,
  [3126] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(866), 1,
      anon_sym_LBRACK,
  [3133] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(868), 1,
      anon_sym_LPAREN,
  [3140] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(870), 1,
      anon_sym_LPAREN,
  [3147] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(872), 1,
      anon_sym_COMMA,
  [3154] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(874), 1,
      anon_sym_COMMA,
  [3161] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(876), 1,
      anon_sym_COMMA,
  [3168] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(878), 1,
      anon_sym_LPAREN,
  [3175] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(880), 1,
      anon_sym_LPAREN,
  [3182] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(882), 1,
      anon_sym_COMMA,
  [3189] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(884), 1,
      anon_sym_LPAREN,
  [3196] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(886), 1,
      anon_sym_LPAREN,
  [3203] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(888), 1,
      sym_string,
  [3210] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(890), 1,
      anon_sym_COMMA,
  [3217] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(892), 1,
      anon_sym_LPAREN,
  [3224] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(894), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(90)] = 0,
  [SMALL_STATE(91)] = 87,
  [SMALL_STATE(92)] = 165,
  [SMALL_STATE(93)] = 227,
  [SMALL_STATE(94)] = 289,
  [SMALL_STATE(95)] = 351,
  [SMALL_STATE(96)] = 413,
  [SMALL_STATE(97)] = 475,
  [SMALL_STATE(98)] = 537,
  [SMALL_STATE(99)] = 599,
  [SMALL_STATE(100)] = 661,
  [SMALL_STATE(101)] = 723,
  [SMALL_STATE(102)] = 785,
  [SMALL_STATE(103)] = 847,
  [SMALL_STATE(104)] = 909,
  [SMALL_STATE(105)] = 971,
  [SMALL_STATE(106)] = 1033,
  [SMALL_STATE(107)] = 1057,
  [SMALL_STATE(108)] = 1081,
  [SMALL_STATE(109)] = 1107,
  [SMALL_STATE(110)] = 1131,
  [SMALL_STATE(111)] = 1183,
  [SMALL_STATE(112)] = 1207,
  [SMALL_STATE(113)] = 1231,
  [SMALL_STATE(114)] = 1255,
  [SMALL_STATE(115)] = 1279,
  [SMALL_STATE(116)] = 1303,
  [SMALL_STATE(117)] = 1327,
  [SMALL_STATE(118)] = 1351,
  [SMALL_STATE(119)] = 1375,
  [SMALL_STATE(120)] = 1399,
  [SMALL_STATE(121)] = 1421,
  [SMALL_STATE(122)] = 1443,
  [SMALL_STATE(123)] = 1464,
  [SMALL_STATE(124)] = 1487,
  [SMALL_STATE(125)] = 1508,
  [SMALL_STATE(126)] = 1551,
  [SMALL_STATE(127)] = 1572,
  [SMALL_STATE(128)] = 1593,
  [SMALL_STATE(129)] = 1618,
  [SMALL_STATE(130)] = 1639,
  [SMALL_STATE(131)] = 1651,
  [SMALL_STATE(132)] = 1664,
  [SMALL_STATE(133)] = 1679,
  [SMALL_STATE(134)] = 1694,
  [SMALL_STATE(135)] = 1708,
  [SMALL_STATE(136)] = 1722,
  [SMALL_STATE(137)] = 1736,
  [SMALL_STATE(138)] = 1748,
  [SMALL_STATE(139)] = 1762,
  [SMALL_STATE(140)] = 1774,
  [SMALL_STATE(141)] = 1784,
  [SMALL_STATE(142)] = 1794,
  [SMALL_STATE(143)] = 1805,
  [SMALL_STATE(144)] = 1814,
  [SMALL_STATE(145)] = 1825,
  [SMALL_STATE(146)] = 1838,
  [SMALL_STATE(147)] = 1849,
  [SMALL_STATE(148)] = 1862,
  [SMALL_STATE(149)] = 1875,
  [SMALL_STATE(150)] = 1888,
  [SMALL_STATE(151)] = 1901,
  [SMALL_STATE(152)] = 1912,
  [SMALL_STATE(153)] = 1922,
  [SMALL_STATE(154)] = 1930,
  [SMALL_STATE(155)] = 1940,
  [SMALL_STATE(156)] = 1950,
  [SMALL_STATE(157)] = 1960,
  [SMALL_STATE(158)] = 1970,
  [SMALL_STATE(159)] = 1980,
  [SMALL_STATE(160)] = 1990,
  [SMALL_STATE(161)] = 2000,
  [SMALL_STATE(162)] = 2010,
  [SMALL_STATE(163)] = 2020,
  [SMALL_STATE(164)] = 2030,
  [SMALL_STATE(165)] = 2040,
  [SMALL_STATE(166)] = 2050,
  [SMALL_STATE(167)] = 2060,
  [SMALL_STATE(168)] = 2070,
  [SMALL_STATE(169)] = 2080,
  [SMALL_STATE(170)] = 2090,
  [SMALL_STATE(171)] = 2100,
  [SMALL_STATE(172)] = 2110,
  [SMALL_STATE(173)] = 2120,
  [SMALL_STATE(174)] = 2130,
  [SMALL_STATE(175)] = 2140,
  [SMALL_STATE(176)] = 2150,
  [SMALL_STATE(177)] = 2160,
  [SMALL_STATE(178)] = 2167,
  [SMALL_STATE(179)] = 2174,
  [SMALL_STATE(180)] = 2181,
  [SMALL_STATE(181)] = 2188,
  [SMALL_STATE(182)] = 2195,
  [SMALL_STATE(183)] = 2202,
  [SMALL_STATE(184)] = 2209,
  [SMALL_STATE(185)] = 2216,
  [SMALL_STATE(186)] = 2223,
  [SMALL_STATE(187)] = 2230,
  [SMALL_STATE(188)] = 2237,
  [SMALL_STATE(189)] = 2244,
  [SMALL_STATE(190)] = 2251,
  [SMALL_STATE(191)] = 2258,
  [SMALL_STATE(192)] = 2265,
  [SMALL_STATE(193)] = 2272,
  [SMALL_STATE(194)] = 2279,
  [SMALL_STATE(195)] = 2286,
  [SMALL_STATE(196)] = 2293,
  [SMALL_STATE(197)] = 2300,
  [SMALL_STATE(198)] = 2307,
  [SMALL_STATE(199)] = 2314,
  [SMALL_STATE(200)] = 2321,
  [SMALL_STATE(201)] = 2328,
  [SMALL_STATE(202)] = 2335,
  [SMALL_STATE(203)] = 2342,
  [SMALL_STATE(204)] = 2349,
  [SMALL_STATE(205)] = 2356,
  [SMALL_STATE(206)] = 2363,
  [SMALL_STATE(207)] = 2370,
  [SMALL_STATE(208)] = 2377,
  [SMALL_STATE(209)] = 2384,
  [SMALL_STATE(210)] = 2391,
  [SMALL_STATE(211)] = 2398,
  [SMALL_STATE(212)] = 2405,
  [SMALL_STATE(213)] = 2412,
  [SMALL_STATE(214)] = 2419,
  [SMALL_STATE(215)] = 2426,
  [SMALL_STATE(216)] = 2433,
  [SMALL_STATE(217)] = 2440,
  [SMALL_STATE(218)] = 2447,
  [SMALL_STATE(219)] = 2454,
  [SMALL_STATE(220)] = 2461,
  [SMALL_STATE(221)] = 2468,
  [SMALL_STATE(222)] = 2475,
  [SMALL_STATE(223)] = 2482,
  [SMALL_STATE(224)] = 2489,
  [SMALL_STATE(225)] = 2496,
  [SMALL_STATE(226)] = 2503,
  [SMALL_STATE(227)] = 2510,
  [SMALL_STATE(228)] = 2517,
  [SMALL_STATE(229)] = 2524,
  [SMALL_STATE(230)] = 2531,
  [SMALL_STATE(231)] = 2538,
  [SMALL_STATE(232)] = 2545,
  [SMALL_STATE(233)] = 2552,
  [SMALL_STATE(234)] = 2559,
  [SMALL_STATE(235)] = 2566,
  [SMALL_STATE(236)] = 2573,
  [SMALL_STATE(237)] = 2580,
  [SMALL_STATE(238)] = 2587,
  [SMALL_STATE(239)] = 2594,
  [SMALL_STATE(240)] = 2601,
  [SMALL_STATE(241)] = 2608,
  [SMALL_STATE(242)] = 2615,
  [SMALL_STATE(243)] = 2622,
  [SMALL_STATE(244)] = 2629,
  [SMALL_STATE(245)] = 2636,
  [SMALL_STATE(246)] = 2643,
  [SMALL_STATE(247)] = 2650,
  [SMALL_STATE(248)] = 2657,
  [SMALL_STATE(249)] = 2664,
  [SMALL_STATE(250)] = 2671,
  [SMALL_STATE(251)] = 2678,
  [SMALL_STATE(252)] = 2685,
  [SMALL_STATE(253)] = 2692,
  [SMALL_STATE(254)] = 2699,
  [SMALL_STATE(255)] = 2706,
  [SMALL_STATE(256)] = 2713,
  [SMALL_STATE(257)] = 2720,
  [SMALL_STATE(258)] = 2727,
  [SMALL_STATE(259)] = 2734,
  [SMALL_STATE(260)] = 2741,
  [SMALL_STATE(261)] = 2748,
  [SMALL_STATE(262)] = 2755,
  [SMALL_STATE(263)] = 2762,
  [SMALL_STATE(264)] = 2769,
  [SMALL_STATE(265)] = 2776,
  [SMALL_STATE(266)] = 2783,
  [SMALL_STATE(267)] = 2790,
  [SMALL_STATE(268)] = 2797,
  [SMALL_STATE(269)] = 2804,
  [SMALL_STATE(270)] = 2811,
  [SMALL_STATE(271)] = 2818,
  [SMALL_STATE(272)] = 2825,
  [SMALL_STATE(273)] = 2832,
  [SMALL_STATE(274)] = 2839,
  [SMALL_STATE(275)] = 2846,
  [SMALL_STATE(276)] = 2853,
  [SMALL_STATE(277)] = 2860,
  [SMALL_STATE(278)] = 2867,
  [SMALL_STATE(279)] = 2874,
  [SMALL_STATE(280)] = 2881,
  [SMALL_STATE(281)] = 2888,
  [SMALL_STATE(282)] = 2895,
  [SMALL_STATE(283)] = 2902,
  [SMALL_STATE(284)] = 2909,
  [SMALL_STATE(285)] = 2916,
  [SMALL_STATE(286)] = 2923,
  [SMALL_STATE(287)] = 2930,
  [SMALL_STATE(288)] = 2937,
  [SMALL_STATE(289)] = 2944,
  [SMALL_STATE(290)] = 2951,
  [SMALL_STATE(291)] = 2958,
  [SMALL_STATE(292)] = 2965,
  [SMALL_STATE(293)] = 2972,
  [SMALL_STATE(294)] = 2979,
  [SMALL_STATE(295)] = 2986,
  [SMALL_STATE(296)] = 2993,
  [SMALL_STATE(297)] = 3000,
  [SMALL_STATE(298)] = 3007,
  [SMALL_STATE(299)] = 3014,
  [SMALL_STATE(300)] = 3021,
  [SMALL_STATE(301)] = 3028,
  [SMALL_STATE(302)] = 3035,
  [SMALL_STATE(303)] = 3042,
  [SMALL_STATE(304)] = 3049,
  [SMALL_STATE(305)] = 3056,
  [SMALL_STATE(306)] = 3063,
  [SMALL_STATE(307)] = 3070,
  [SMALL_STATE(308)] = 3077,
  [SMALL_STATE(309)] = 3084,
  [SMALL_STATE(310)] = 3091,
  [SMALL_STATE(311)] = 3098,
  [SMALL_STATE(312)] = 3105,
  [SMALL_STATE(313)] = 3112,
  [SMALL_STATE(314)] = 3119,
  [SMALL_STATE(315)] = 3126,
  [SMALL_STATE(316)] = 3133,
  [SMALL_STATE(317)] = 3140,
  [SMALL_STATE(318)] = 3147,
  [SMALL_STATE(319)] = 3154,
  [SMALL_STATE(320)] = 3161,
  [SMALL_STATE(321)] = 3168,
  [SMALL_STATE(322)] = 3175,
  [SMALL_STATE(323)] = 3182,
  [SMALL_STATE(324)] = 3189,
  [SMALL_STATE(325)] = 3196,
  [SMALL_STATE(326)] = 3203,
  [SMALL_STATE(327)] = 3210,
  [SMALL_STATE(328)] = 3217,
  [SMALL_STATE(329)] = 3224,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(201),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(328),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(322),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(321),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(311),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(310),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(309),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(308),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(301),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(298),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(121),
  [37] = {.entry = {.count = 1, .reusable = false}}, SHIFT(130),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(130),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [43] = {.entry = {.count = 1, .reusable = false}}, SHIFT(68),
  [45] = {.entry = {.count = 1, .reusable = true}}, SHIFT(297),
  [47] = {.entry = {.count = 1, .reusable = false}}, SHIFT(297),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(296),
  [51] = {.entry = {.count = 1, .reusable = true}}, SHIFT(277),
  [53] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3),
  [57] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(201),
  [60] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(5),
  [63] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(328),
  [66] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(322),
  [69] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(321),
  [72] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(311),
  [75] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(310),
  [78] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(309),
  [81] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(308),
  [84] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(301),
  [87] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(298),
  [90] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(51),
  [93] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(66),
  [96] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(121),
  [99] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(121),
  [102] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(130),
  [105] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(130),
  [108] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(68),
  [111] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(68),
  [114] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(297),
  [117] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(297),
  [120] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(296),
  [123] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(277),
  [126] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(22),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1, .production_id = 1),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [133] = {.entry = {.count = 1, .reusable = true}}, SHIFT(223),
  [135] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [137] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 19),
  [139] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 19),
  [141] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 6),
  [143] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 6),
  [145] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__boollike_field, 4, .production_id = 13),
  [147] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__boollike_field, 4, .production_id = 13),
  [149] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 7, .production_id = 28),
  [151] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 7, .production_id = 28),
  [153] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [155] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [157] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 5, .production_id = 18),
  [159] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 5, .production_id = 18),
  [161] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1, .production_id = 1),
  [163] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1, .production_id = 1),
  [165] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 6),
  [167] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 6),
  [169] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 5),
  [171] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [173] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [175] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [177] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [179] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 5),
  [181] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [183] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [185] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 6, .production_id = 27),
  [187] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 6, .production_id = 27),
  [189] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__bool_lhs, 1, .production_id = 1),
  [191] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__bool_lhs, 1, .production_id = 1),
  [193] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [195] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [197] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 7),
  [199] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 7),
  [201] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [203] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [205] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 7),
  [207] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 7),
  [209] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 4),
  [211] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 4),
  [213] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [215] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [217] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [219] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [221] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2, .production_id = 2),
  [223] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2, .production_id = 2),
  [225] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1, .production_id = 1),
  [227] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [229] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [231] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1, .production_id = 1),
  [233] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [235] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [237] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 4, .production_id = 13),
  [239] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 4, .production_id = 13),
  [241] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [243] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [245] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(324),
  [248] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3),
  [250] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(316),
  [253] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(306),
  [256] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(329),
  [259] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(325),
  [262] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(317),
  [265] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(307),
  [268] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(86),
  [271] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(68),
  [274] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(68),
  [277] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(297),
  [280] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(297),
  [283] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(296),
  [286] = {.entry = {.count = 1, .reusable = true}}, SHIFT(324),
  [288] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [290] = {.entry = {.count = 1, .reusable = true}}, SHIFT(316),
  [292] = {.entry = {.count = 1, .reusable = true}}, SHIFT(306),
  [294] = {.entry = {.count = 1, .reusable = true}}, SHIFT(329),
  [296] = {.entry = {.count = 1, .reusable = true}}, SHIFT(325),
  [298] = {.entry = {.count = 1, .reusable = true}}, SHIFT(317),
  [300] = {.entry = {.count = 1, .reusable = true}}, SHIFT(307),
  [302] = {.entry = {.count = 1, .reusable = true}}, SHIFT(86),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(106),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(261),
  [308] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(204),
  [312] = {.entry = {.count = 1, .reusable = true}}, SHIFT(202),
  [314] = {.entry = {.count = 1, .reusable = true}}, SHIFT(289),
  [316] = {.entry = {.count = 1, .reusable = true}}, SHIFT(195),
  [318] = {.entry = {.count = 1, .reusable = true}}, SHIFT(193),
  [320] = {.entry = {.count = 1, .reusable = true}}, SHIFT(192),
  [322] = {.entry = {.count = 1, .reusable = true}}, SHIFT(191),
  [324] = {.entry = {.count = 1, .reusable = true}}, SHIFT(153),
  [326] = {.entry = {.count = 1, .reusable = true}}, SHIFT(171),
  [328] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [330] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [332] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [334] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [336] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [338] = {.entry = {.count = 1, .reusable = true}}, SHIFT(88),
  [340] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [342] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [344] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [346] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [348] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [350] = {.entry = {.count = 1, .reusable = true}}, SHIFT(254),
  [352] = {.entry = {.count = 1, .reusable = true}}, SHIFT(248),
  [354] = {.entry = {.count = 1, .reusable = true}}, SHIFT(168),
  [356] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 22),
  [358] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 22),
  [360] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 20),
  [362] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 20),
  [364] = {.entry = {.count = 1, .reusable = true}}, SHIFT(173),
  [366] = {.entry = {.count = 1, .reusable = true}}, SHIFT(249),
  [368] = {.entry = {.count = 1, .reusable = false}}, SHIFT(249),
  [370] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 8, .production_id = 30),
  [372] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 8, .production_id = 30),
  [374] = {.entry = {.count = 1, .reusable = true}}, SHIFT(174),
  [376] = {.entry = {.count = 1, .reusable = true}}, SHIFT(233),
  [378] = {.entry = {.count = 1, .reusable = true}}, SHIFT(231),
  [380] = {.entry = {.count = 1, .reusable = true}}, SHIFT(230),
  [382] = {.entry = {.count = 1, .reusable = true}}, SHIFT(229),
  [384] = {.entry = {.count = 1, .reusable = true}}, SHIFT(228),
  [386] = {.entry = {.count = 1, .reusable = true}}, SHIFT(227),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(222),
  [390] = {.entry = {.count = 1, .reusable = true}}, SHIFT(221),
  [392] = {.entry = {.count = 1, .reusable = false}}, SHIFT(220),
  [394] = {.entry = {.count = 1, .reusable = true}}, SHIFT(219),
  [396] = {.entry = {.count = 1, .reusable = false}}, SHIFT(218),
  [398] = {.entry = {.count = 1, .reusable = true}}, SHIFT(217),
  [400] = {.entry = {.count = 1, .reusable = true}}, SHIFT(216),
  [402] = {.entry = {.count = 1, .reusable = true}}, SHIFT(214),
  [404] = {.entry = {.count = 1, .reusable = true}}, SHIFT(211),
  [406] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 25),
  [408] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 25),
  [410] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 24),
  [412] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 24),
  [414] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [416] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [418] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 5, .production_id = 16),
  [420] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 5, .production_id = 16),
  [422] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 12),
  [424] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 12),
  [426] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 10),
  [428] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 10),
  [430] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 9),
  [432] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 9),
  [434] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__numberlike_field, 4, .production_id = 13),
  [436] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__numberlike_field, 4, .production_id = 13),
  [438] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [440] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [442] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__number_lhs, 1, .production_id = 1),
  [444] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__number_lhs, 1, .production_id = 1),
  [446] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [448] = {.entry = {.count = 1, .reusable = true}}, SHIFT(246),
  [450] = {.entry = {.count = 1, .reusable = false}}, SHIFT(246),
  [452] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 10),
  [454] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 10),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [458] = {.entry = {.count = 1, .reusable = true}}, SHIFT(258),
  [460] = {.entry = {.count = 1, .reusable = true}}, SHIFT(257),
  [462] = {.entry = {.count = 1, .reusable = true}}, SHIFT(256),
  [464] = {.entry = {.count = 1, .reusable = true}}, SHIFT(255),
  [466] = {.entry = {.count = 1, .reusable = true}}, SHIFT(178),
  [468] = {.entry = {.count = 1, .reusable = true}}, SHIFT(253),
  [470] = {.entry = {.count = 1, .reusable = true}}, SHIFT(252),
  [472] = {.entry = {.count = 1, .reusable = true}}, SHIFT(251),
  [474] = {.entry = {.count = 1, .reusable = false}}, SHIFT(250),
  [476] = {.entry = {.count = 1, .reusable = true}}, SHIFT(247),
  [478] = {.entry = {.count = 1, .reusable = false}}, SHIFT(245),
  [480] = {.entry = {.count = 1, .reusable = true}}, SHIFT(236),
  [482] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 9),
  [484] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 9),
  [486] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [488] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [490] = {.entry = {.count = 1, .reusable = true}}, SHIFT(150),
  [492] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [494] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [496] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(12),
  [499] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [501] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [503] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [505] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [507] = {.entry = {.count = 1, .reusable = true}}, SHIFT(234),
  [509] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2),
  [511] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2), SHIFT_REPEAT(137),
  [514] = {.entry = {.count = 1, .reusable = true}}, SHIFT(143),
  [516] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 1),
  [518] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [520] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 5, .production_id = 14),
  [522] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 2),
  [524] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [526] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(145),
  [529] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [531] = {.entry = {.count = 1, .reusable = true}}, SHIFT(145),
  [533] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [535] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(148),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(148),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(139),
  [544] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [546] = {.entry = {.count = 1, .reusable = true}}, SHIFT(156),
  [548] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [550] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [552] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 8, .production_id = 29),
  [554] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 8, .production_id = 29),
  [556] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [558] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_array, 6, .production_id = 26),
  [560] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_array, 6, .production_id = 26),
  [562] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 23),
  [564] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 23),
  [566] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 21),
  [568] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 21),
  [570] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 17),
  [572] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 17),
  [574] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 15),
  [576] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 15),
  [578] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 14),
  [580] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 14),
  [582] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 4, .production_id = 8),
  [584] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 4, .production_id = 8),
  [586] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 11),
  [588] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 11),
  [590] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [592] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [594] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 1),
  [596] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 1),
  [598] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 1),
  [600] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 1),
  [602] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_number_field, 1),
  [604] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_number_field, 1),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(203),
  [608] = {.entry = {.count = 1, .reusable = false}}, SHIFT(208),
  [610] = {.entry = {.count = 1, .reusable = false}}, SHIFT(210),
  [612] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [614] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(154),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(295),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(232),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [624] = {.entry = {.count = 1, .reusable = false}}, SHIFT(206),
  [626] = {.entry = {.count = 1, .reusable = true}}, SHIFT(238),
  [628] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [630] = {.entry = {.count = 1, .reusable = true}}, SHIFT(200),
  [632] = {.entry = {.count = 1, .reusable = true}}, SHIFT(199),
  [634] = {.entry = {.count = 1, .reusable = true}}, SHIFT(224),
  [636] = {.entry = {.count = 1, .reusable = true}}, SHIFT(198),
  [638] = {.entry = {.count = 1, .reusable = true}}, SHIFT(177),
  [640] = {.entry = {.count = 1, .reusable = true}}, SHIFT(196),
  [642] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [644] = {.entry = {.count = 1, .reusable = true}}, SHIFT(194),
  [646] = {.entry = {.count = 1, .reusable = true}}, SHIFT(175),
  [648] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [650] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [652] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [654] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [656] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [658] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [660] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [662] = {.entry = {.count = 1, .reusable = true}}, SHIFT(237),
  [664] = {.entry = {.count = 1, .reusable = true}}, SHIFT(213),
  [666] = {.entry = {.count = 1, .reusable = true}}, SHIFT(239),
  [668] = {.entry = {.count = 1, .reusable = true}}, SHIFT(240),
  [670] = {.entry = {.count = 1, .reusable = true}}, SHIFT(241),
  [672] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [674] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [676] = {.entry = {.count = 1, .reusable = true}}, SHIFT(242),
  [678] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [680] = {.entry = {.count = 1, .reusable = true}}, SHIFT(181),
  [682] = {.entry = {.count = 1, .reusable = true}}, SHIFT(259),
  [684] = {.entry = {.count = 1, .reusable = true}}, SHIFT(278),
  [686] = {.entry = {.count = 1, .reusable = true}}, SHIFT(279),
  [688] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [690] = {.entry = {.count = 1, .reusable = true}}, SHIFT(243),
  [692] = {.entry = {.count = 1, .reusable = true}}, SHIFT(244),
  [694] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [696] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [698] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [700] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [702] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [704] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [706] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [708] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [710] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [712] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [714] = {.entry = {.count = 1, .reusable = true}}, SHIFT(299),
  [716] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [718] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [720] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [722] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [724] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [726] = {.entry = {.count = 1, .reusable = true}}, SHIFT(263),
  [728] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [730] = {.entry = {.count = 1, .reusable = true}}, SHIFT(123),
  [732] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [734] = {.entry = {.count = 1, .reusable = true}}, SHIFT(264),
  [736] = {.entry = {.count = 1, .reusable = true}}, SHIFT(265),
  [738] = {.entry = {.count = 1, .reusable = true}}, SHIFT(266),
  [740] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [742] = {.entry = {.count = 1, .reusable = true}}, SHIFT(111),
  [744] = {.entry = {.count = 1, .reusable = true}}, SHIFT(269),
  [746] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [748] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [750] = {.entry = {.count = 1, .reusable = true}}, SHIFT(271),
  [752] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [754] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [756] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [758] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [760] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [762] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [764] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [766] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [768] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [770] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [772] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [774] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [776] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [778] = {.entry = {.count = 1, .reusable = true}}, SHIFT(273),
  [780] = {.entry = {.count = 1, .reusable = true}}, SHIFT(274),
  [782] = {.entry = {.count = 1, .reusable = true}}, SHIFT(205),
  [784] = {.entry = {.count = 1, .reusable = true}}, SHIFT(206),
  [786] = {.entry = {.count = 1, .reusable = true}}, SHIFT(208),
  [788] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [790] = {.entry = {.count = 1, .reusable = true}}, SHIFT(210),
  [792] = {.entry = {.count = 1, .reusable = true}}, SHIFT(276),
  [794] = {.entry = {.count = 1, .reusable = true}}, SHIFT(109),
  [796] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [798] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [800] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [802] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [804] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [806] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [808] = {.entry = {.count = 1, .reusable = true}}, SHIFT(207),
  [810] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [812] = {.entry = {.count = 1, .reusable = true}}, SHIFT(209),
  [814] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [816] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [818] = {.entry = {.count = 1, .reusable = true}}, SHIFT(212),
  [820] = {.entry = {.count = 1, .reusable = true}}, SHIFT(101),
  [822] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [824] = {.entry = {.count = 1, .reusable = true}}, SHIFT(215),
  [826] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [828] = {.entry = {.count = 1, .reusable = true}}, SHIFT(164),
  [830] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [832] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [834] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [836] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [838] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [840] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [842] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [844] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [846] = {.entry = {.count = 1, .reusable = true}}, SHIFT(155),
  [848] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [850] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [852] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [854] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [856] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
  [858] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [860] = {.entry = {.count = 1, .reusable = true}}, SHIFT(302),
  [862] = {.entry = {.count = 1, .reusable = true}}, SHIFT(303),
  [864] = {.entry = {.count = 1, .reusable = true}}, SHIFT(304),
  [866] = {.entry = {.count = 1, .reusable = true}}, SHIFT(305),
  [868] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [870] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [872] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [874] = {.entry = {.count = 1, .reusable = true}}, SHIFT(312),
  [876] = {.entry = {.count = 1, .reusable = true}}, SHIFT(313),
  [878] = {.entry = {.count = 1, .reusable = true}}, SHIFT(83),
  [880] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [882] = {.entry = {.count = 1, .reusable = true}}, SHIFT(314),
  [884] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [886] = {.entry = {.count = 1, .reusable = true}}, SHIFT(94),
  [888] = {.entry = {.count = 1, .reusable = true}}, SHIFT(323),
  [890] = {.entry = {.count = 1, .reusable = true}}, SHIFT(326),
  [892] = {.entry = {.count = 1, .reusable = true}}, SHIFT(85),
  [894] = {.entry = {.count = 1, .reusable = true}}, SHIFT(95),
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
