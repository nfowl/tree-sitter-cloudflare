module.exports = grammar({
  name: 'cloudflare',

  rules: {
    //TODO AAAAAAAAAAAAAAAAA
    source_file: $ => repeat($._expression),

    _expression: $ => choice(
      $.not_expression,
      $.compound_expression,
      $.group,
      $.simple_expression,
    ),

    not_expression: $ => prec(4,seq(
      $.not_operator,
      // choice('not','!'),
      $._expression,
    )),

    compound_expression: $ => choice(
      prec(3,$._and_expression),
      prec(2,$._xor_expression),
      prec(1,$._or_expression),
    ),

    _and_expression: $ => prec.left(3,seq(
      $._expression,
      $.and_operator,
      $._expression,
    )),

    _xor_expression: $ => prec.left(2,seq(
      $._expression,
      $.xor_operator,
      $._expression,
    )),

    _or_expression: $ => prec.left(1,seq(
      $._expression,
      $.or_operator,
      $._expression,
    )),

    not_operator: $ => choice(
      'not', '!'
    ),

    and_operator: $ => choice(
      'and','&&'
    ),

    xor_operator: $ => choice(
      'xor','^^'
    ),

    or_operator: $ => choice(
      'or','||'
    ),

    simple_expression: $ => seq(
      $._field,
      $.comparison_operator,
      $._value
    ),

    _field: $ => choice(
      $.string_field,
      $.number_field,
      $.boolean_field,
      // $.list_field,
      // $.map_field
    ),

    group: $ => seq(
      '(',
      $._expression,
      ')',
    ),

    _value: $ => choice(
      $.number,
      $.boolean,
    ),

    number: $ => /\d+/,

    boolean: $ => choice(
      'true',
      'false',
    ),

    logical_operator: $ => choice(
      prec(4, choice('not','!')),
      prec(3, choice('and','&&')),
      prec(2, choice('xor','^^')),
      prec(1, choice('or','||')),
    ),

    comparison_operator: $ => choice(
      '==',
      'eq',
    ),

    number_field: $ => choice(
      'cf.edge.server_port',
      'cf.waf.score',
    ),

    string_field: $ => choice(
      'cf.bot_management.ja3_hash'
    ),
    boolean_field: $ => choice(
      'ssl',
    ),
  }
})
