//! Combinator based strace output parser

use std::{collections::HashSet, iter};

use nix::libc::pid_t;
use nom::{
    IResult, Parser as _,
    branch::alt,
    bytes::complete::{is_not, tag, take, take_until},
    character::complete::{
        self, alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, space1,
    },
    combinator::{map, map_opt, map_res, opt, peek, recognize, rest, value, verify},
    multi::{count, many_till, many0_count, separated_list0, separated_list1},
    number::complete::double,
    sequence::{delimited, pair, preceded, separated_pair, terminated},
};

use super::ParseLineResult;
use crate::strace::{
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
    NamedSymbol, Syscall,
    parser::{ParsedSyscall, SyscallEnd, SyscallStart},
};

macro_rules! dbg_parser_entry {
    ($input:expr) => {
        log::trace!("{}:{}\ninput: {:?}", function_name!(), line!(), $input)
    };
}

macro_rules! dbg_parser_success {
    ($output:expr) => {
        log::trace!("{}:{}\nparsed: {:?}", function_name!(), line!(), $output)
    };
}

/// Parse a strace line
pub(crate) fn parse_line(
    line: &str,
    names_complete: &HashSet<&str>,
) -> anyhow::Result<ParseLineResult> {
    match parse_syscall_line(line, names_complete).map(|s| s.1) {
        Err(nom::Err::Incomplete(_) | nom::Err::Error(_)) => Ok(ParseLineResult::Ignored),
        Err(nom::Err::Failure(e)) => Err(anyhow::anyhow!("{e}")),
        Ok(res) => Ok(res),
    }
}

// Main line token parsers

#[function_name::named]
fn parse_syscall_line<'a>(
    i: &'a str,
    names_complete: &HashSet<&str>,
) -> IResult<&'a str, ParseLineResult> {
    // Parse common prefix (pid + timestamp)
    let (i, (pid, rel_ts)) = (parse_pid, parse_rel_ts).parse(i)?;

    alt((
        // Finished syscall
        map(
            (
                delimited(tag("<... "), parse_name, (tag(" resumed> )"), space1)),
                parse_ret_val,
            ),
            |(name, ret_val)| {
                if names_complete.contains(name) {
                    ParseLineResult::Parsed(ParsedSyscall::SyscallEnd(SyscallEnd {
                        pid,
                        rel_ts,
                        name: name.into(),
                        ret_val,
                    }))
                } else {
                    ParseLineResult::Parsed(ParsedSyscall::NameOnly {
                        name: name.into(),
                        ret_val,
                    })
                }
            },
        ),
        // Complete syscall
        map(
            (
                verify(parse_name, |name: &str| names_complete.contains(name)),
                parse_args_complete,
                parse_ret_val,
            ),
            |(name, args, ret_val)| {
                ParseLineResult::Parsed(ParsedSyscall::Syscall(Syscall {
                    pid,
                    rel_ts,
                    name: name.into(),
                    args,
                    ret_val,
                }))
            },
        ),
        // Unfinished syscall
        map(
            (
                verify(parse_name, |name: &str| names_complete.contains(name)),
                parse_args_incomplete,
            ),
            |(name, args)| {
                ParseLineResult::Parsed(ParsedSyscall::SyscallStart(SyscallStart {
                    pid,
                    rel_ts,
                    name: name.into(),
                    args,
                }))
            },
        ),
        // "name only" syscall
        map(
            (
                verify(parse_name, |name: &str| !names_complete.contains(name)),
                skip_args,
                parse_ret_val,
            ),
            |(name, (), ret_val)| {
                ParseLineResult::Parsed(ParsedSyscall::NameOnly {
                    name: name.into(),
                    ret_val,
                })
            },
        ),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_pid(i: &str) -> IResult<&str, pid_t> {
    dbg_parser_entry!(i);
    terminated(map_res(digit1, str::parse), space1)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_rel_ts(i: &str) -> IResult<&str, f64> {
    dbg_parser_entry!(i);
    terminated(double, space1)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_name(i: &str) -> IResult<&str, &str> {
    dbg_parser_entry!(i);
    parse_symbol(i)
}

#[function_name::named]
fn skip_balanced_parens(i: &str) -> IResult<&str, ()> {
    delimited(
        char('('),
        many0_count(alt((map(is_not("()"), |_: &str| ()), skip_balanced_parens))),
        char(')'),
    )
    .map(|_| ())
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn skip_args(i: &str) -> IResult<&str, ()> {
    terminated(skip_balanced_parens, space1)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_args_complete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    delimited(char('('), parse_args_inner, terminated(char(')'), space1))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_args_incomplete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    delimited(char('('), parse_args_inner, tag(" <unfinished ...>"))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_args_inner(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    alt((
        map(separated_list1(tag(", "), parse_struct_member), |ne| {
            // Named arguments are stuffed in a single struct
            vec![Expression::Struct(
                ne.into_iter().map(|(n, e)| (n.to_owned(), e)).collect(),
            )]
        }),
        separated_list0(
            tag(", "),
            alt((
                map(parse_in_out_argument, |(ia, oa)| ia.unwrap_or(oa)),
                parse_expression,
            )),
        ),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_in_out_argument(i: &str) -> IResult<&str, (Option<Expression>, Expression)> {
    dbg_parser_entry!(i);
    alt((
        map(
            alt((
                separated_pair(parse_expression, tag(" => "), parse_expression),
                delimited(
                    char('['),
                    separated_pair(parse_expression, tag(" => "), parse_expression),
                    char(']'),
                ),
            )),
            |(ia, oa)| (Some(ia), oa),
        ),
        map(delimited(tag("[{"), parse_expression, tag("}]")), |oa| {
            (None, oa)
        }),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_ret_val(i: &str) -> IResult<&str, Option<IntegerExpression>> {
    dbg_parser_entry!(i);
    preceded(
        terminated(char('='), space1),
        map_opt(
            (
                alt((map(parse_int_literal, Some), value(None, char('?')))),
                opt(preceded(space1, rest)),
            ),
            |(ieo, m): (Option<IntegerExpression>, Option<&str>)| {
                if let Some(mut ie) = ieo {
                    if let Some(m) = m
                        && ie.metadata.replace(m.as_bytes().to_vec()).is_some()
                    {
                        // We already had some metadata, something is wrong
                        return None;
                    }
                    Some(Some(ie))
                } else {
                    Some(None)
                }
            },
        ),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Shared parsers

#[function_name::named]
fn parse_symbol(i: &str) -> IResult<&str, &str> {
    dbg_parser_entry!(i);
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_comment(i: &str) -> IResult<&str, Option<&str>> {
    dbg_parser_entry!(i);
    opt(delimited(tag(" /* "), take_until(" */"), tag(" */")))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

// Expression

#[function_name::named]
fn parse_expression(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        pair(
            alt((
                parse_expression_mac_addr,
                parse_expression_int,
                parse_expression_struct,
                parse_expression_buf,
                parse_expression_set,
                parse_expression_array,
            )),
            parse_comment,
        ),
        |(u, _)| u,
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_mac_addr(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        (
            map_res(take(2_usize), |s| u8::from_str_radix(s, 16)),
            count(
                map_res(preceded(char(':'), take(2_usize)), |s| {
                    u8::from_str_radix(s, 16)
                }),
                5,
            ),
        ),
        |(f, o)| {
            let mut mac = [0; 6];
            mac[0] = f;
            mac[1..].copy_from_slice(&o);
            Expression::MacAddress(mac)
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_macro_pseudo_address(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(preceded(char('&'), parse_symbol), |s| {
        Expression::DestinationAddress(s.to_owned())
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_int(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(parse_int, Expression::Integer)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_struct(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        delimited(
            char('{'),
            separated_list0(
                tag(", "),
                alt((
                    map(parse_struct_member, |(n, e)| (n.to_owned(), e)),
                    map_opt(parse_int_macro, |e| -> Option<(String, Expression)> {
                        if let IntegerExpression {
                            value: IntegerExpressionValue::Macro { args, .. },
                            ..
                        } = &e
                        {
                            args.iter().find_map(|a| {
                                if let Expression::DestinationAddress(n) = a {
                                    Some((n.to_owned(), Expression::Integer(e.clone())))
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    }),
                )),
            ),
            (opt(tag(", ...")), char('}')),
        ),
        |m| Expression::Struct(m.into_iter().collect()),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_buf(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(parse_buffer, Expression::Buffer)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_set(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        pair(
            opt(char('~')),
            delimited(
                char('['),
                separated_list0(char(' '), parse_int),
                (opt(tag(" ...")), char(']')),
            ),
        ),
        |(neg, values)| Expression::Collection {
            complement: neg.is_some(),
            values: values
                .into_iter()
                .map(|ie| (None, Expression::Integer(ie)))
                .collect(),
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_array(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        delimited(
            char('['),
            separated_list0(
                tag(", "),
                (
                    opt(terminated(
                        delimited(char('['), terminated(parse_int, parse_comment), char(']')),
                        char('='),
                    )),
                    parse_expression,
                ),
            ),
            char(']'),
        ),
        |values| Expression::Collection {
            complement: false,
            values,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Int expression

#[function_name::named]
fn parse_int(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    alt((parse_int_unnamed, parse_int_named))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_operand(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    alt((parse_int_unnamed, parse_int_named_unambiguous))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

/// Parse an integer expression other than a bare symbol name
#[function_name::named]
fn parse_int_unnamed(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    alt((
        parse_int_bit_or,
        parse_int_bool_and,
        parse_int_equals,
        parse_int_macro,
        parse_int_multiplication,
        parse_int_substraction,
        parse_int_left_shift,
        parse_int_literal,
        parse_int_negation,
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_bit_or(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        terminated(
            separated_pair(
                alt((parse_int_left_shift, parse_int_named_unambiguous)),
                char('|'),
                separated_list1(char('|'), parse_int_operand),
            ),
            opt(char('|')),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::BinaryOr(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::BinaryOr(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_bool_and(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_macro,
            tag(" && "),
            separated_list1(tag(" && "), parse_int_operand),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::BooleanAnd(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::BooleanAnd(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_equals(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_macro,
            tag(" == "),
            separated_list1(tag(" == "), parse_int_operand),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Equality(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Equality(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_macro(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        pair(
            parse_symbol,
            delimited(
                char('('),
                separated_list0(
                    tag(", "),
                    alt((parse_expression_macro_pseudo_address, parse_expression)),
                ),
                char(')'),
            ),
        ),
        |(n, args)| IntegerExpression {
            value: IntegerExpressionValue::Macro {
                name: n.to_owned(),
                args,
            },
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_multiplication(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_literal,
            char('*'),
            separated_list1(char('*'), parse_int_operand),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Multiplication(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Multiplication(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_substraction(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_named_unambiguous,
            char('-'),
            separated_list1(char('-'), parse_int_operand),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Substraction(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Substraction(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        (
            alt((
                parse_int_literal_hexa,
                parse_int_literal_oct,
                parse_int_literal_dec,
            )),
            parse_int_metadata,
        ),
        |(v, m)| IntegerExpression {
            value: IntegerExpressionValue::Literal(v),
            metadata: m,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_left_shift(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            alt((parse_int_literal, parse_int_named_unambiguous)),
            tag("<<"),
            alt((
                parse_int_literal,
                parse_int_named_unambiguous,
                delimited(char('('), parse_int_operand, char(')')),
            )),
        ),
        |(b, s)| IntegerExpression {
            value: IntegerExpressionValue::LeftBitShift {
                bits: Box::new(b.value),
                shift: Box::new(s.value),
            },
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_negation(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(preceded(char('-'), parse_int_named_unambiguous), |e| {
        IntegerExpression {
            value: IntegerExpressionValue::Negation(Box::new(e.value)),
            metadata: None,
        }
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_named(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    alt((parse_int_named_ambiguous, parse_int_named_unambiguous))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_named_ambiguous(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_symbol,
            tag(" or "),
            separated_list1(tag(" or "), parse_symbol),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Ambiguous(
                iter::once(f).chain(rs).map(str::to_owned).collect(),
            )),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_named_unambiguous(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map((parse_symbol, parse_int_metadata), |(e, metadata)| {
        IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(e.to_owned())),
            metadata,
        }
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_metadata(i: &str) -> IResult<&str, Option<Vec<u8>>> {
    dbg_parser_entry!(i);
    opt(delimited(
        char('<'),
        map(many_till(parse_buffer_byte, char('>')), |r| r.0),
        opt(tag("(deleted)")),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Int literal

#[function_name::named]
fn parse_int_literal_hexa(i: &str) -> IResult<&str, i64> {
    dbg_parser_entry!(i);
    // Parse as u64 and reinterpret bits as i64, so that values above i64::MAX
    // (eg. pointer addresses like 0xFFFFFFFFFFFFFFFF) are represented as negative i64
    preceded(
        tag("0x"),
        map_res(hex_digit1, |s| {
            u64::from_str_radix(s, 16).map(u64::cast_signed)
        }),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal_oct(i: &str) -> IResult<&str, i64> {
    dbg_parser_entry!(i);
    preceded(
        char('0'),
        map_res(oct_digit1, |s| i64::from_str_radix(s, 8)),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal_dec(i: &str) -> IResult<&str, i64> {
    dbg_parser_entry!(i);
    complete::i64(i)
}

// Buffer

#[function_name::named]
fn parse_buffer(i: &str) -> IResult<&str, BufferExpression> {
    dbg_parser_entry!(i);
    map(
        terminated(
            pair(
                opt(char('@')),
                preceded(
                    char('"'),
                    map(many_till(parse_buffer_byte, char('"')), |r| r.0),
                ),
            ),
            opt(tag("...")),
        ),
        |(a, r)| BufferExpression {
            value: r,
            type_: if a.is_some() {
                BufferType::AbstractPath
            } else {
                BufferType::Unknown
            },
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_buffer_byte(i: &str) -> IResult<&str, u8> {
    dbg_parser_entry!(i);
    map_res(preceded(tag("\\x"), take(2_usize)), |s| {
        u8::from_str_radix(s, 16)
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Struct

#[function_name::named]
fn parse_struct_member(i: &str) -> IResult<&str, (&str, Expression)> {
    dbg_parser_entry!(i);
    separated_pair(
        parse_symbol,
        char('='),
        alt((
            map(parse_in_out_argument, |(ia, oa)| ia.unwrap_or(oa)),
            parse_expression,
            // Empty flag set
            value(
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::BinaryOr(vec![]),
                    metadata: None,
                }),
                peek(alt((tag(", "), tag("}")))),
            ),
        )),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn parse_expression_array_works() {
        assert_eq!(
            parse_expression_array(
                "[[IPV4_DEVCONF_BC_FORWARDING-1]=0, [IPV4_DEVCONF_ARP_EVICT_NOCARRIER-1]=1, [37 /* IPSTATS_MIB_??? */]=22]"
            )
            .unwrap(),
            (
                "",
                Expression::Collection {
                    complement: false,
                    values: vec![
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Substraction(vec![
                                    IntegerExpressionValue::NamedSymbol(
                                        NamedSymbol::Unambiguous(
                                            "IPV4_DEVCONF_BC_FORWARDING".to_owned()
                                        )
                                    ),
                                    IntegerExpressionValue::Literal(1)
                                ]),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            })
                        ),
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Substraction(vec![
                                    IntegerExpressionValue::NamedSymbol(
                                        NamedSymbol::Unambiguous(
                                            "IPV4_DEVCONF_ARP_EVICT_NOCARRIER".to_owned()
                                        )
                                    ),
                                    IntegerExpressionValue::Literal(1)
                                ]),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1),
                                metadata: None
                            })
                        ),
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Literal(37),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(22),
                                metadata: None
                            })
                        )
                    ]
                }
            )
        );
    }

    #[test]
    fn parse_expression_struct_final_empty_member() {
        assert_eq!(
            parse_expression("{c_iflag=}").unwrap(),
            (
                "",
                Expression::Struct(HashMap::from([(
                    "c_iflag".to_owned(),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![]),
                        metadata: None,
                    }),
                )]))
            )
        );
    }

    #[test]
    fn skip_args_empty() {
        // getpid() = 641314
        assert_eq!(skip_args("() ").unwrap(), ("", ()));
    }

    #[test]
    fn skip_args_simple_flat() {
        // mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f52a332e000
        assert_eq!(
            skip_args("(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) ")
                .unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_struct_arg() {
        // rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) = 0
        assert_eq!(
            skip_args("(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_nested_macro_calls() {
        // bind(6<...>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr("\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31")}, 16) = 0
        assert_eq!(
            skip_args(r#"(6<...>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr("\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31")}, 16) "#).unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_makedev_nested() {
        // fstat(3<path>, {st_dev=makedev(0, 0x1b), st_ino=1682452, ...}) = 0
        assert_eq!(
            skip_args("(3<path>, {st_dev=makedev(0, 0x1b), st_ino=1682452, ...}) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_predicate_macros() {
        // wait4(30247, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 30247
        assert_eq!(
            skip_args("(30247, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_inet_pton_three_arg_macro() {
        // connect(93, {inet_pton(AF_INET6, "\x12\x34", &sin6_addr), sin6_scope_id=0}, 28) = 0
        assert_eq!(
            skip_args(r#"(93, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "\x12\x34", &sin6_addr), sin6_scope_id=0}, 28) "#).unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_fd_deleted_annotation() {
        // write(16<\x2f\x6d\x65\x6d\x66\x64\x3a...>(deleted), "\x20\x00"..., 856) = 856
        // (deleted) is balanced parens inside the outer args
        assert_eq!(
            skip_args(r#"(16<\x2f\x6d\x65\x6d\x66\x64>(deleted), "\x20\x00"..., 856) "#).unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_clone3_in_out() {
        // clone3({flags=CLONE_VM|..., stack=0x7f3b7b800000} => {parent_tid=[664773]}, 88) = 664773
        assert_eq!(
            skip_args("({flags=CLONE_VM|CLONE_FS, child_tid=0x748ef7218ce8, stack=0x748ef6a18000, stack_size=0x7ff6c0} => {parent_tid=[311668]}, 88) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_four_level_nesting() {
        // sendmsg with msg_control=[{cmsg_data={pid=311662, uid=1000, gid=1000}}]
        assert_eq!(
            skip_args("(8<...>, {msg_name=NULL, msg_iov=[{iov_base=\"\\x00\", iov_len=1}], msg_iovlen=1, msg_control=[{cmsg_len=28, cmsg_level=SOL_SOCKET, cmsg_type=SCM_CREDENTIALS, cmsg_data={pid=311662, uid=1000, gid=1000}}], msg_controllen=32, msg_flags=0}, MSG_NOSIGNAL) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_epoll_pwait_array_of_structs() {
        // epoll_pwait(4<...>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}], 128, 0, NULL, 0) = 2
        assert_eq!(
            skip_args("(4<...>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}, {events=EPOLLOUT, data={u32=800587777, u64=9163493471925305345}}], 128, 0, NULL, 0) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_prlimit64_multiplication() {
        // prlimit64(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) = 0
        assert_eq!(
            skip_args("(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_leaves_remainder() {
        // Verify skip_args leaves the return value as remainder
        assert_eq!(skip_args("(NULL, 8192) = 0").unwrap(), ("= 0", ()));
    }

    #[test]
    fn skip_args_no_trailing_space() {
        // Missing trailing space after closing paren should fail
        assert!(skip_args("()").is_err());
    }

    #[test]
    fn skip_args_unbalanced_open() {
        // Unbalanced parens should fail
        assert!(skip_args("((abc) ").is_err());
    }

    #[test]
    fn skip_args_no_open_paren() {
        // No opening paren should fail
        assert!(skip_args("abc) ").is_err());
    }

    #[test]
    fn skip_args_sendto_netlink_mixed_array() {
        // sendto with [{struct}, "raw bytes"] mixed array
        assert_eq!(
            skip_args(r#"(5<...>, [{nlmsg_len=40, nlmsg_type=0x14, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|0x600, nlmsg_seq=0, nlmsg_pid=1}, "\x02\x08\x80\xfe"], 40, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) "#).unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_capset_bitshift() {
        // capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_SYS_CHROOT, permitted=1<<CAP_SYS_CHROOT, inheritable=0}) = 0
        assert_eq!(
            skip_args("({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_SYS_CHROOT, permitted=1<<CAP_SYS_CHROOT, inheritable=0}) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_ioctl_double_nested_brackets() {
        // ioctl with c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, ...]
        assert_eq!(
            skip_args("(2<path>, TCGETS2, {c_iflag=ICRNL|IXON|IUTF8, c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, [VERASE]=0x7f], c_ispeed=38400, c_ospeed=38400}) ").unwrap(),
            ("", ())
        );
    }

    #[test]
    fn skip_args_recvfrom_nested_error_struct() {
        // recvfrom with nested nlmsg error containing msg={...}
        assert_eq!(
            skip_args("(5<...>, [{nlmsg_len=36, nlmsg_type=NLMSG_ERROR, nlmsg_flags=NLM_F_CAPPED}, {error=0, msg={nlmsg_len=40, nlmsg_type=0x14 /* NLMSG_??? */, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|0x600}}], 1024, 0, NULL, NULL) ").unwrap(),
            ("", ())
        );
    }
}
