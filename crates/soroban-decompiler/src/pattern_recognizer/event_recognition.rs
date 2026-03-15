//! Event struct pattern matching.
//!
//! Recognizes raw `env.events().publish(args, data)` calls and transforms
//! them into `EventStruct { field: data }.publish(&env)` when a matching
//! `EventV0` spec entry exists.

use stellar_xdr::curr::ScSpecEntry;

use crate::ir::{Expr, Literal, MethodCall, Statement};

/// Recognize raw `env.events().publish(args, data)` and transform to
/// `EventStruct { field: data }.publish(&env)` when matching EventV0 exists.
///
/// Looks for a pair: `let args = vec![&env, topic1, topic2]` followed by
/// `env.events().publish(args, data)`. Matches topic strings against
/// EventV0 spec entries.
pub(super) fn recognize_event_structs(
    stmts: Vec<Statement>,
    all_entries: &[ScSpecEntry],
) -> Vec<Statement> {
    // Find EventV0 specs
    let events: Vec<_> = all_entries.iter().filter_map(|e| {
        if let ScSpecEntry::EventV0(ev) = e {
            Some(ev)
        } else { None }
    }).collect();
    if events.is_empty() { return stmts; }

    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;
    while i < stmts.len() {
        // Look for: let args = vec![&env, topic1, topic2]
        // followed by: env.events().publish(args, data)
        if i + 1 < stmts.len() {
            if let (Some(topics_var), Some(data_expr)) = (
                try_extract_vec_topics(&stmts[i]),
                try_extract_event_publish(&stmts[i + 1]),
            ) {
                // Check if the publish references the topics var
                if data_expr.0 == topics_var.0 {
                    // Try to match topics against event specs
                    if let Some(event_stmt) = match_event_spec(&events, &topics_var.1, &data_expr.1) {
                        result.push(event_stmt);
                        i += 2; // skip both statements
                        continue;
                    }
                }
            }
        }
        // Recurse into nested blocks
        result.push(match stmts[i].clone() {
            Statement::If { condition, then_body, else_body } => Statement::If {
                condition,
                then_body: recognize_event_structs(then_body, all_entries),
                else_body: recognize_event_structs(else_body, all_entries),
            },
            other => other,
        });
        i += 1;
    }
    result
}

/// Extract (var_name, topic_strings) from `let VAR = vec![&env, sym1, sym2]`
fn try_extract_vec_topics(stmt: &Statement) -> Option<(String, Vec<String>)> {
    if let Statement::Let { name, value: Expr::MacroCall { name: mac, args }, .. } = stmt {
        if mac != "vec" { return None; }
        let topics: Vec<String> = args.iter().skip(1) // skip &env
            .filter_map(|a| match a {
                Expr::MacroCall { name, args } if name == "symbol_short" => {
                    if let Some(Expr::Literal(Literal::Str(s))) = args.first() {
                        Some(s.clone())
                    } else { None }
                }
                _ => None,
            })
            .collect();
        if !topics.is_empty() {
            return Some((name.clone(), topics));
        }
    }
    None
}

/// Extract (topics_var, data_expr) from `env.events().publish(VAR, DATA)`
fn try_extract_event_publish(stmt: &Statement) -> Option<(String, Expr)> {
    if let Statement::Expr(Expr::MethodChain { receiver, calls }) = stmt {
        if !matches!(receiver.as_ref(), Expr::Var(n) if n == "env") { return None; }
        if calls.len() != 2 { return None; }
        if calls[0].name != "events" || calls[1].name != "publish" { return None; }
        if calls[1].args.len() < 2 { return None; }
        if let Expr::Var(var_name) = &calls[1].args[0] {
            return Some((var_name.clone(), calls[1].args[1].clone()));
        }
    }
    None
}

/// Match topic strings against EventV0 specs and build a struct publish.
fn match_event_spec(
    events: &[&stellar_xdr::curr::ScSpecEventV0],
    topics: &[String],
    data: &Expr,
) -> Option<Statement> {
    for ev in events {
        // Event topics from spec
        let ev_topics: Vec<String> = ev.params.iter()
            .filter(|p| matches!(
                p.location,
                stellar_xdr::curr::ScSpecEventParamLocationV0::TopicList,
            ))
            .map(|p| p.name.to_utf8_string_lossy())
            .collect();
        let data_fields: Vec<String> = ev.params.iter()
            .filter(|p| matches!(
                p.location,
                stellar_xdr::curr::ScSpecEventParamLocationV0::Data,
            ))
            .map(|p| p.name.to_utf8_string_lossy())
            .collect();

        // Match: topic strings from our vec should correspond to the event
        // Some events use the event name as first topic, some use custom topics.
        // Check if any topic string matches the event name (case-insensitive).
        let ev_name = ev.name.to_utf8_string_lossy();
        let name_in_topics = topics.iter().any(|t| {
            t.eq_ignore_ascii_case(&ev_name) || ev_name.to_lowercase().contains(&t.to_lowercase())
        });

        // Also match if topic count matches event topic param count
        let topics_match = topics.len() == ev_topics.len() + 1 // +1 for event name topic
            || topics.len() == ev_topics.len();

        if (name_in_topics || topics_match) && !data_fields.is_empty() {
            let fields: Vec<(String, Expr)> = data_fields.iter()
                .map(|f| (f.clone(), data.clone()))
                .collect();
            let event_struct = Expr::StructLiteral {
                name: ev_name,
                fields,
            };
            return Some(Statement::Expr(Expr::MethodChain {
                receiver: Box::new(event_struct),
                calls: vec![MethodCall {
                    name: "publish".into(),
                    args: vec![Expr::Var("&env".into())],
                }],
            }));
        }
    }
    None
}
