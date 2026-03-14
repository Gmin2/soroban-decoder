use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtStructV0};

/// Find a spec struct whose field names match the given key list.
///
/// Soroban struct fields are sorted alphabetically in the serialized form,
/// matching the order of keys in map_new_from_linear_memory.
pub(super) fn find_struct_by_fields<'a>(
    keys: &[String],
    all_entries: &'a [ScSpecEntry],
) -> Option<&'a ScSpecUdtStructV0> {
    for entry in all_entries {
        if let ScSpecEntry::UdtStructV0(s) = entry {
            let spec_fields: Vec<String> = s.fields.iter()
                .map(|f| f.name.to_utf8_string_lossy())
                .collect();
            // Spec fields sorted alphabetically to match map key order.
            let mut sorted_fields = spec_fields.clone();
            sorted_fields.sort();
            if sorted_fields == keys {
                return Some(s);
            }
        }
    }
    None
}

/// Convert a PascalCase or camelCase name to snake_case.
pub(super) fn to_snake_case(name: &str) -> String {
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap_or(ch));
    }
    result
}
