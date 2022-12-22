#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 32
#define LARGE_STATE_COUNT 4
#define SYMBOL_COUNT 41
#define ALIAS_COUNT 0
#define TOKEN_COUNT 20
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 0
#define MAX_ALIAS_SEQUENCE_LENGTH 3
#define PRODUCTION_ID_COUNT 1

enum {
  anon_sym_not = 1,
  anon_sym_BANG = 2,
  anon_sym_and = 3,
  anon_sym_AMP_AMP = 4,
  anon_sym_xor = 5,
  anon_sym_CARET_CARET = 6,
  anon_sym_or = 7,
  anon_sym_PIPE_PIPE = 8,
  anon_sym_LPAREN = 9,
  anon_sym_RPAREN = 10,
  sym_number = 11,
  anon_sym_true = 12,
  anon_sym_false = 13,
  anon_sym_EQ_EQ = 14,
  anon_sym_eq = 15,
  anon_sym_cf_DOTedge_DOTserver_port = 16,
  anon_sym_cf_DOTwaf_DOTscore = 17,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 18,
  anon_sym_ssl = 19,
  sym_source_file = 20,
  sym__expression = 21,
  sym_not_expression = 22,
  sym_compound_expression = 23,
  sym__and_expression = 24,
  sym__xor_expression = 25,
  sym__or_expression = 26,
  sym_not_operator = 27,
  sym_and_operator = 28,
  sym_xor_operator = 29,
  sym_or_operator = 30,
  sym_simple_expression = 31,
  sym__field = 32,
  sym_group = 33,
  sym__value = 34,
  sym_boolean = 35,
  sym_comparison_operator = 36,
  sym_number_field = 37,
  sym_string_field = 38,
  sym_boolean_field = 39,
  aux_sym_source_file_repeat1 = 40,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_not] = "not",
  [anon_sym_BANG] = "!",
  [anon_sym_and] = "and",
  [anon_sym_AMP_AMP] = "&&",
  [anon_sym_xor] = "xor",
  [anon_sym_CARET_CARET] = "^^",
  [anon_sym_or] = "or",
  [anon_sym_PIPE_PIPE] = "||",
  [anon_sym_LPAREN] = "(",
  [anon_sym_RPAREN] = ")",
  [sym_number] = "number",
  [anon_sym_true] = "true",
  [anon_sym_false] = "false",
  [anon_sym_EQ_EQ] = "==",
  [anon_sym_eq] = "eq",
  [anon_sym_cf_DOTedge_DOTserver_port] = "cf.edge.server_port",
  [anon_sym_cf_DOTwaf_DOTscore] = "cf.waf.score",
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = "cf.bot_management.ja3_hash",
  [anon_sym_ssl] = "ssl",
  [sym_source_file] = "source_file",
  [sym__expression] = "_expression",
  [sym_not_expression] = "not_expression",
  [sym_compound_expression] = "compound_expression",
  [sym__and_expression] = "_and_expression",
  [sym__xor_expression] = "_xor_expression",
  [sym__or_expression] = "_or_expression",
  [sym_not_operator] = "not_operator",
  [sym_and_operator] = "and_operator",
  [sym_xor_operator] = "xor_operator",
  [sym_or_operator] = "or_operator",
  [sym_simple_expression] = "simple_expression",
  [sym__field] = "_field",
  [sym_group] = "group",
  [sym__value] = "_value",
  [sym_boolean] = "boolean",
  [sym_comparison_operator] = "comparison_operator",
  [sym_number_field] = "number_field",
  [sym_string_field] = "string_field",
  [sym_boolean_field] = "boolean_field",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [anon_sym_not] = anon_sym_not,
  [anon_sym_BANG] = anon_sym_BANG,
  [anon_sym_and] = anon_sym_and,
  [anon_sym_AMP_AMP] = anon_sym_AMP_AMP,
  [anon_sym_xor] = anon_sym_xor,
  [anon_sym_CARET_CARET] = anon_sym_CARET_CARET,
  [anon_sym_or] = anon_sym_or,
  [anon_sym_PIPE_PIPE] = anon_sym_PIPE_PIPE,
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [sym_number] = sym_number,
  [anon_sym_true] = anon_sym_true,
  [anon_sym_false] = anon_sym_false,
  [anon_sym_EQ_EQ] = anon_sym_EQ_EQ,
  [anon_sym_eq] = anon_sym_eq,
  [anon_sym_cf_DOTedge_DOTserver_port] = anon_sym_cf_DOTedge_DOTserver_port,
  [anon_sym_cf_DOTwaf_DOTscore] = anon_sym_cf_DOTwaf_DOTscore,
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = anon_sym_cf_DOTbot_management_DOTja3_hash,
  [anon_sym_ssl] = anon_sym_ssl,
  [sym_source_file] = sym_source_file,
  [sym__expression] = sym__expression,
  [sym_not_expression] = sym_not_expression,
  [sym_compound_expression] = sym_compound_expression,
  [sym__and_expression] = sym__and_expression,
  [sym__xor_expression] = sym__xor_expression,
  [sym__or_expression] = sym__or_expression,
  [sym_not_operator] = sym_not_operator,
  [sym_and_operator] = sym_and_operator,
  [sym_xor_operator] = sym_xor_operator,
  [sym_or_operator] = sym_or_operator,
  [sym_simple_expression] = sym_simple_expression,
  [sym__field] = sym__field,
  [sym_group] = sym_group,
  [sym__value] = sym__value,
  [sym_boolean] = sym_boolean,
  [sym_comparison_operator] = sym_comparison_operator,
  [sym_number_field] = sym_number_field,
  [sym_string_field] = sym_string_field,
  [sym_boolean_field] = sym_boolean_field,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
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
  [anon_sym_and] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_AMP_AMP] = {
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
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
    .visible = true,
    .named = false,
  },
  [sym_number] = {
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
  [anon_sym_EQ_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_eq] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTedge_DOTserver_port] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssl] = {
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
  [sym_compound_expression] = {
    .visible = true,
    .named = true,
  },
  [sym__and_expression] = {
    .visible = false,
    .named = true,
  },
  [sym__xor_expression] = {
    .visible = false,
    .named = true,
  },
  [sym__or_expression] = {
    .visible = false,
    .named = true,
  },
  [sym_not_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_and_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_xor_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_or_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_simple_expression] = {
    .visible = true,
    .named = true,
  },
  [sym__field] = {
    .visible = false,
    .named = true,
  },
  [sym_group] = {
    .visible = true,
    .named = true,
  },
  [sym__value] = {
    .visible = false,
    .named = true,
  },
  [sym_boolean] = {
    .visible = true,
    .named = true,
  },
  [sym_comparison_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_number_field] = {
    .visible = true,
    .named = true,
  },
  [sym_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_boolean_field] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_source_file_repeat1] = {
    .visible = false,
    .named = false,
  },
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
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(70);
      if (lookahead == '!') ADVANCE(72);
      if (lookahead == '&') ADVANCE(1);
      if (lookahead == '(') ADVANCE(79);
      if (lookahead == ')') ADVANCE(80);
      if (lookahead == '=') ADVANCE(7);
      if (lookahead == '^') ADVANCE(8);
      if (lookahead == 'a') ADVANCE(41);
      if (lookahead == 'c') ADVANCE(30);
      if (lookahead == 'e') ADVANCE(50);
      if (lookahead == 'f') ADVANCE(12);
      if (lookahead == 'n') ADVANCE(44);
      if (lookahead == 'o') ADVANCE(51);
      if (lookahead == 's') ADVANCE(59);
      if (lookahead == 't') ADVANCE(52);
      if (lookahead == 'x') ADVANCE(46);
      if (lookahead == '|') ADVANCE(69);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(81);
      END_STATE();
    case 1:
      if (lookahead == '&') ADVANCE(74);
      END_STATE();
    case 2:
      if (lookahead == '.') ADVANCE(18);
      END_STATE();
    case 3:
      if (lookahead == '.') ADVANCE(36);
      END_STATE();
    case 4:
      if (lookahead == '.') ADVANCE(58);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(62);
      END_STATE();
    case 6:
      if (lookahead == '3') ADVANCE(11);
      END_STATE();
    case 7:
      if (lookahead == '=') ADVANCE(84);
      END_STATE();
    case 8:
      if (lookahead == '^') ADVANCE(76);
      END_STATE();
    case 9:
      if (lookahead == '_') ADVANCE(39);
      END_STATE();
    case 10:
      if (lookahead == '_') ADVANCE(49);
      END_STATE();
    case 11:
      if (lookahead == '_') ADVANCE(35);
      END_STATE();
    case 12:
      if (lookahead == 'a') ADVANCE(38);
      END_STATE();
    case 13:
      if (lookahead == 'a') ADVANCE(6);
      END_STATE();
    case 14:
      if (lookahead == 'a') ADVANCE(43);
      END_STATE();
    case 15:
      if (lookahead == 'a') ADVANCE(61);
      END_STATE();
    case 16:
      if (lookahead == 'a') ADVANCE(31);
      END_STATE();
    case 17:
      if (lookahead == 'a') ADVANCE(33);
      END_STATE();
    case 18:
      if (lookahead == 'b') ADVANCE(45);
      if (lookahead == 'e') ADVANCE(21);
      if (lookahead == 'w') ADVANCE(16);
      END_STATE();
    case 19:
      if (lookahead == 'c') ADVANCE(47);
      END_STATE();
    case 20:
      if (lookahead == 'd') ADVANCE(73);
      END_STATE();
    case 21:
      if (lookahead == 'd') ADVANCE(32);
      END_STATE();
    case 22:
      if (lookahead == 'e') ADVANCE(82);
      END_STATE();
    case 23:
      if (lookahead == 'e') ADVANCE(83);
      END_STATE();
    case 24:
      if (lookahead == 'e') ADVANCE(87);
      END_STATE();
    case 25:
      if (lookahead == 'e') ADVANCE(40);
      END_STATE();
    case 26:
      if (lookahead == 'e') ADVANCE(42);
      END_STATE();
    case 27:
      if (lookahead == 'e') ADVANCE(5);
      END_STATE();
    case 28:
      if (lookahead == 'e') ADVANCE(54);
      END_STATE();
    case 29:
      if (lookahead == 'e') ADVANCE(55);
      END_STATE();
    case 30:
      if (lookahead == 'f') ADVANCE(2);
      END_STATE();
    case 31:
      if (lookahead == 'f') ADVANCE(4);
      END_STATE();
    case 32:
      if (lookahead == 'g') ADVANCE(27);
      END_STATE();
    case 33:
      if (lookahead == 'g') ADVANCE(25);
      END_STATE();
    case 34:
      if (lookahead == 'h') ADVANCE(88);
      END_STATE();
    case 35:
      if (lookahead == 'h') ADVANCE(15);
      END_STATE();
    case 36:
      if (lookahead == 'j') ADVANCE(13);
      END_STATE();
    case 37:
      if (lookahead == 'l') ADVANCE(89);
      END_STATE();
    case 38:
      if (lookahead == 'l') ADVANCE(60);
      END_STATE();
    case 39:
      if (lookahead == 'm') ADVANCE(14);
      END_STATE();
    case 40:
      if (lookahead == 'm') ADVANCE(26);
      END_STATE();
    case 41:
      if (lookahead == 'n') ADVANCE(20);
      END_STATE();
    case 42:
      if (lookahead == 'n') ADVANCE(66);
      END_STATE();
    case 43:
      if (lookahead == 'n') ADVANCE(17);
      END_STATE();
    case 44:
      if (lookahead == 'o') ADVANCE(63);
      END_STATE();
    case 45:
      if (lookahead == 'o') ADVANCE(64);
      END_STATE();
    case 46:
      if (lookahead == 'o') ADVANCE(53);
      END_STATE();
    case 47:
      if (lookahead == 'o') ADVANCE(57);
      END_STATE();
    case 48:
      if (lookahead == 'o') ADVANCE(56);
      END_STATE();
    case 49:
      if (lookahead == 'p') ADVANCE(48);
      END_STATE();
    case 50:
      if (lookahead == 'q') ADVANCE(85);
      END_STATE();
    case 51:
      if (lookahead == 'r') ADVANCE(77);
      END_STATE();
    case 52:
      if (lookahead == 'r') ADVANCE(67);
      END_STATE();
    case 53:
      if (lookahead == 'r') ADVANCE(75);
      END_STATE();
    case 54:
      if (lookahead == 'r') ADVANCE(68);
      END_STATE();
    case 55:
      if (lookahead == 'r') ADVANCE(10);
      END_STATE();
    case 56:
      if (lookahead == 'r') ADVANCE(65);
      END_STATE();
    case 57:
      if (lookahead == 'r') ADVANCE(24);
      END_STATE();
    case 58:
      if (lookahead == 's') ADVANCE(19);
      END_STATE();
    case 59:
      if (lookahead == 's') ADVANCE(37);
      END_STATE();
    case 60:
      if (lookahead == 's') ADVANCE(23);
      END_STATE();
    case 61:
      if (lookahead == 's') ADVANCE(34);
      END_STATE();
    case 62:
      if (lookahead == 's') ADVANCE(28);
      END_STATE();
    case 63:
      if (lookahead == 't') ADVANCE(71);
      END_STATE();
    case 64:
      if (lookahead == 't') ADVANCE(9);
      END_STATE();
    case 65:
      if (lookahead == 't') ADVANCE(86);
      END_STATE();
    case 66:
      if (lookahead == 't') ADVANCE(3);
      END_STATE();
    case 67:
      if (lookahead == 'u') ADVANCE(22);
      END_STATE();
    case 68:
      if (lookahead == 'v') ADVANCE(29);
      END_STATE();
    case 69:
      if (lookahead == '|') ADVANCE(78);
      END_STATE();
    case 70:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 71:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 72:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 73:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 74:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 75:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 76:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 77:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 78:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 79:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 80:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 81:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(81);
      END_STATE();
    case 82:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 83:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 84:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 85:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 86:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 87:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      END_STATE();
    case 88:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 89:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 0},
  [2] = {.lex_state = 0},
  [3] = {.lex_state = 0},
  [4] = {.lex_state = 0},
  [5] = {.lex_state = 0},
  [6] = {.lex_state = 0},
  [7] = {.lex_state = 0},
  [8] = {.lex_state = 0},
  [9] = {.lex_state = 0},
  [10] = {.lex_state = 0},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 0},
  [13] = {.lex_state = 0},
  [14] = {.lex_state = 0},
  [15] = {.lex_state = 0},
  [16] = {.lex_state = 0},
  [17] = {.lex_state = 0},
  [18] = {.lex_state = 0},
  [19] = {.lex_state = 0},
  [20] = {.lex_state = 0},
  [21] = {.lex_state = 0},
  [22] = {.lex_state = 0},
  [23] = {.lex_state = 0},
  [24] = {.lex_state = 0},
  [25] = {.lex_state = 0},
  [26] = {.lex_state = 0},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 0},
  [29] = {.lex_state = 0},
  [30] = {.lex_state = 0},
  [31] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_not] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_and] = ACTIONS(1),
    [anon_sym_AMP_AMP] = ACTIONS(1),
    [anon_sym_xor] = ACTIONS(1),
    [anon_sym_CARET_CARET] = ACTIONS(1),
    [anon_sym_or] = ACTIONS(1),
    [anon_sym_PIPE_PIPE] = ACTIONS(1),
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
    [anon_sym_EQ_EQ] = ACTIONS(1),
    [anon_sym_eq] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(1),
    [anon_sym_ssl] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(31),
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym__and_expression] = STATE(18),
    [sym__xor_expression] = STATE(14),
    [sym__or_expression] = STATE(16),
    [sym_not_operator] = STATE(8),
    [sym_simple_expression] = STATE(13),
    [sym__field] = STATE(27),
    [sym_group] = STATE(13),
    [sym_number_field] = STATE(27),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(3),
    [anon_sym_not] = ACTIONS(5),
    [anon_sym_BANG] = ACTIONS(5),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(11),
    [anon_sym_ssl] = ACTIONS(13),
  },
  [2] = {
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym__and_expression] = STATE(18),
    [sym__xor_expression] = STATE(14),
    [sym__or_expression] = STATE(16),
    [sym_not_operator] = STATE(8),
    [sym_simple_expression] = STATE(13),
    [sym__field] = STATE(27),
    [sym_group] = STATE(13),
    [sym_number_field] = STATE(27),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(15),
    [anon_sym_not] = ACTIONS(17),
    [anon_sym_BANG] = ACTIONS(17),
    [anon_sym_LPAREN] = ACTIONS(20),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(23),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(26),
    [anon_sym_ssl] = ACTIONS(29),
  },
  [3] = {
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym__and_expression] = STATE(18),
    [sym__xor_expression] = STATE(14),
    [sym__or_expression] = STATE(16),
    [sym_not_operator] = STATE(8),
    [sym_simple_expression] = STATE(13),
    [sym__field] = STATE(27),
    [sym_group] = STATE(13),
    [sym_number_field] = STATE(27),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(32),
    [anon_sym_not] = ACTIONS(5),
    [anon_sym_BANG] = ACTIONS(5),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(11),
    [anon_sym_ssl] = ACTIONS(13),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 11,
    ACTIONS(7), 1,
      anon_sym_LPAREN,
    ACTIONS(11), 1,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
    ACTIONS(13), 1,
      anon_sym_ssl,
    STATE(8), 1,
      sym_not_operator,
    STATE(14), 1,
      sym__xor_expression,
    STATE(16), 1,
      sym__or_expression,
    STATE(18), 1,
      sym__and_expression,
    ACTIONS(5), 2,
      anon_sym_not,
      anon_sym_BANG,
    ACTIONS(9), 2,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
    STATE(27), 4,
      sym__field,
      sym_number_field,
      sym_string_field,
      sym_boolean_field,
    STATE(12), 5,
      sym__expression,
      sym_not_expression,
      sym_compound_expression,
      sym_simple_expression,
      sym_group,
  [43] = 11,
    ACTIONS(7), 1,
      anon_sym_LPAREN,
    ACTIONS(11), 1,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
    ACTIONS(13), 1,
      anon_sym_ssl,
    STATE(8), 1,
      sym_not_operator,
    STATE(14), 1,
      sym__xor_expression,
    STATE(16), 1,
      sym__or_expression,
    STATE(18), 1,
      sym__and_expression,
    ACTIONS(5), 2,
      anon_sym_not,
      anon_sym_BANG,
    ACTIONS(9), 2,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
    STATE(27), 4,
      sym__field,
      sym_number_field,
      sym_string_field,
      sym_boolean_field,
    STATE(20), 5,
      sym__expression,
      sym_not_expression,
      sym_compound_expression,
      sym_simple_expression,
      sym_group,
  [86] = 11,
    ACTIONS(7), 1,
      anon_sym_LPAREN,
    ACTIONS(11), 1,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
    ACTIONS(13), 1,
      anon_sym_ssl,
    STATE(8), 1,
      sym_not_operator,
    STATE(14), 1,
      sym__xor_expression,
    STATE(16), 1,
      sym__or_expression,
    STATE(18), 1,
      sym__and_expression,
    ACTIONS(5), 2,
      anon_sym_not,
      anon_sym_BANG,
    ACTIONS(9), 2,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
    STATE(27), 4,
      sym__field,
      sym_number_field,
      sym_string_field,
      sym_boolean_field,
    STATE(10), 5,
      sym__expression,
      sym_not_expression,
      sym_compound_expression,
      sym_simple_expression,
      sym_group,
  [129] = 11,
    ACTIONS(7), 1,
      anon_sym_LPAREN,
    ACTIONS(11), 1,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
    ACTIONS(13), 1,
      anon_sym_ssl,
    STATE(8), 1,
      sym_not_operator,
    STATE(14), 1,
      sym__xor_expression,
    STATE(16), 1,
      sym__or_expression,
    STATE(18), 1,
      sym__and_expression,
    ACTIONS(5), 2,
      anon_sym_not,
      anon_sym_BANG,
    ACTIONS(9), 2,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
    STATE(27), 4,
      sym__field,
      sym_number_field,
      sym_string_field,
      sym_boolean_field,
    STATE(11), 5,
      sym__expression,
      sym_not_expression,
      sym_compound_expression,
      sym_simple_expression,
      sym_group,
  [172] = 11,
    ACTIONS(7), 1,
      anon_sym_LPAREN,
    ACTIONS(11), 1,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
    ACTIONS(13), 1,
      anon_sym_ssl,
    STATE(8), 1,
      sym_not_operator,
    STATE(14), 1,
      sym__xor_expression,
    STATE(16), 1,
      sym__or_expression,
    STATE(18), 1,
      sym__and_expression,
    ACTIONS(5), 2,
      anon_sym_not,
      anon_sym_BANG,
    ACTIONS(9), 2,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
    STATE(27), 4,
      sym__field,
      sym_number_field,
      sym_string_field,
      sym_boolean_field,
    STATE(9), 5,
      sym__expression,
      sym_not_expression,
      sym_compound_expression,
      sym_simple_expression,
      sym_group,
  [215] = 4,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(34), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [242] = 6,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(38), 2,
      anon_sym_and,
      anon_sym_AMP_AMP,
    ACTIONS(40), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(36), 11,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [273] = 5,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(38), 2,
      anon_sym_and,
      anon_sym_AMP_AMP,
    ACTIONS(42), 13,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [302] = 4,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(44), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [329] = 7,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(38), 2,
      anon_sym_and,
      anon_sym_AMP_AMP,
    ACTIONS(40), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(48), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
    ACTIONS(46), 8,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_LPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [361] = 1,
    ACTIONS(50), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [379] = 1,
    ACTIONS(52), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [397] = 1,
    ACTIONS(50), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [415] = 1,
    ACTIONS(54), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [433] = 1,
    ACTIONS(50), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [451] = 1,
    ACTIONS(56), 15,
      ts_builtin_sym_end,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_and,
      anon_sym_AMP_AMP,
      anon_sym_xor,
      anon_sym_CARET_CARET,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
      anon_sym_LPAREN,
      anon_sym_RPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [469] = 7,
    ACTIONS(58), 1,
      anon_sym_RPAREN,
    STATE(4), 1,
      sym_and_operator,
    STATE(6), 1,
      sym_or_operator,
    STATE(7), 1,
      sym_xor_operator,
    ACTIONS(38), 2,
      anon_sym_and,
      anon_sym_AMP_AMP,
    ACTIONS(40), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(48), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [494] = 1,
    ACTIONS(60), 7,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_LPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [504] = 1,
    ACTIONS(62), 7,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_LPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [514] = 1,
    ACTIONS(64), 7,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_LPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [524] = 1,
    ACTIONS(66), 7,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_LPAREN,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_ssl,
  [534] = 3,
    ACTIONS(68), 1,
      sym_number,
    ACTIONS(70), 2,
      anon_sym_true,
      anon_sym_false,
    STATE(17), 2,
      sym__value,
      sym_boolean,
  [546] = 1,
    ACTIONS(72), 3,
      sym_number,
      anon_sym_true,
      anon_sym_false,
  [552] = 2,
    STATE(25), 1,
      sym_comparison_operator,
    ACTIONS(74), 2,
      anon_sym_EQ_EQ,
      anon_sym_eq,
  [560] = 1,
    ACTIONS(76), 2,
      anon_sym_EQ_EQ,
      anon_sym_eq,
  [565] = 1,
    ACTIONS(78), 2,
      anon_sym_EQ_EQ,
      anon_sym_eq,
  [570] = 1,
    ACTIONS(80), 2,
      anon_sym_EQ_EQ,
      anon_sym_eq,
  [575] = 1,
    ACTIONS(82), 1,
      ts_builtin_sym_end,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(4)] = 0,
  [SMALL_STATE(5)] = 43,
  [SMALL_STATE(6)] = 86,
  [SMALL_STATE(7)] = 129,
  [SMALL_STATE(8)] = 172,
  [SMALL_STATE(9)] = 215,
  [SMALL_STATE(10)] = 242,
  [SMALL_STATE(11)] = 273,
  [SMALL_STATE(12)] = 302,
  [SMALL_STATE(13)] = 329,
  [SMALL_STATE(14)] = 361,
  [SMALL_STATE(15)] = 379,
  [SMALL_STATE(16)] = 397,
  [SMALL_STATE(17)] = 415,
  [SMALL_STATE(18)] = 433,
  [SMALL_STATE(19)] = 451,
  [SMALL_STATE(20)] = 469,
  [SMALL_STATE(21)] = 494,
  [SMALL_STATE(22)] = 504,
  [SMALL_STATE(23)] = 514,
  [SMALL_STATE(24)] = 524,
  [SMALL_STATE(25)] = 534,
  [SMALL_STATE(26)] = 546,
  [SMALL_STATE(27)] = 552,
  [SMALL_STATE(28)] = 560,
  [SMALL_STATE(29)] = 565,
  [SMALL_STATE(30)] = 570,
  [SMALL_STATE(31)] = 575,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [15] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [17] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(24),
  [20] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [23] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(30),
  [26] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [29] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(28),
  [32] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [34] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [36] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__or_expression, 3),
  [38] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [40] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [42] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__xor_expression, 3),
  [44] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__and_expression, 3),
  [46] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [48] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [50] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 1),
  [52] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3),
  [54] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3),
  [56] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [58] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [60] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_and_operator, 1),
  [62] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_or_operator, 1),
  [64] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_xor_operator, 1),
  [66] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [68] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [70] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [72] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_comparison_operator, 1),
  [74] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [76] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean_field, 1),
  [78] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [80] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [82] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
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
