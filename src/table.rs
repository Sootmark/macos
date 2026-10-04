//! Rows read by column name, so that a column a macOS version lacks, or one
//! it added, changes nothing: a missing column reads as NULL.

use sqlite::{Database, Row, Value};

/// A row with its table's column names.
pub(crate) struct Named<'t> {
    columns: &'t [String],
    pub(crate) rowid: i64,
    values: Vec<Value>,
}

impl Named<'_> {
    fn value(&self, column: &str) -> Option<&Value> {
        let at = self
            .columns
            .iter()
            .position(|name| name.eq_ignore_ascii_case(column))?;
        self.values.get(at)
    }

    /// The column's integer; `None` when it is NULL, not an integer, or
    /// not in the table.
    pub(crate) fn integer(&self, column: &str) -> Option<i64> {
        self.value(column).and_then(Value::as_integer)
    }

    /// The column's number, integer or real: SQLite stores a real without
    /// a fraction as an integer in a column of numeric affinity
    /// (`TIMESTAMP`), and Core Data's dates are such columns.
    pub(crate) fn number(&self, column: &str) -> Option<f64> {
        match self.value(column)? {
            Value::Integer(value) => Some(*value as f64),
            Value::Real(value) => Some(*value),
            _ => None,
        }
    }

    /// The column's text; `None` when it is NULL, not text, or not in the
    /// table.
    pub(crate) fn text(&self, column: &str) -> Option<String> {
        self.value(column)
            .and_then(Value::as_text)
            .map(str::to_owned)
    }

    /// The column's text, `None` also when it is `UNUSED`, TCC's
    /// placeholder for a column without a value.
    pub(crate) fn text_used(&self, column: &str) -> Option<String> {
        self.text(column).filter(|text| text != "UNUSED")
    }

    /// The column's bytes; `None` when it is NULL, not a blob, or not in
    /// the table.
    pub(crate) fn blob(&self, column: &str) -> Option<Vec<u8>> {
        match self.value(column)? {
            Value::Blob(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }
}

/// Whether `table` exists and declares `column`.
pub(crate) fn has_column(db: &Database<'_>, table: &str, column: &str) -> bool {
    db.table(table).is_some_and(|t| {
        t.column_names()
            .iter()
            .any(|name| name.eq_ignore_ascii_case(column))
    })
}

/// Every row of `table` in rowid order, converted; none when the table is
/// absent. Damage met on the way is added to `problems`.
pub(crate) fn read<T>(
    db: &Database<'_>,
    table: &str,
    problems: &mut Vec<String>,
    mut convert: impl FnMut(&Named<'_>) -> T,
) -> Vec<T> {
    let Some(columns) = db.table(table).map(|t| {
        t.column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    }) else {
        return Vec::new();
    };
    let mut rows = match db.rows(table) {
        Ok(rows) => rows,
        Err(e) => {
            problems.push(format!("{table}: {e}"));
            return Vec::new();
        }
    };
    let converted = rows
        .by_ref()
        .map(|Row { rowid, values, .. }| {
            convert(&Named {
                columns: &columns,
                rowid,
                values,
            })
        })
        .collect();
    problems.extend(rows.problems().iter().map(|p| format!("{table}: {p}")));
    converted
}
