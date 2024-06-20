# Style configuration for CNDP documentation files.
#
# For details on how to configure, see [markdownlint docs][1].
#
# For explanation of the rules themselves, see [markdownlint's RULES.md][2]
#
# [1]: https://github.com/markdownlint/markdownlint/blob/master/docs/creating_styles.md
# [2]: https://github.com/markdownlint/markdownlint/blob/master/docs/RULES.md

all
rule "ul-indent", indent: 4

rule "ul-style", style: :dash
rule "no-duplicate-header", allow_different_nesting: true
rule "line-length", :line_length => 165
rule 'MD010', :indent => 3
# exclude_rule 'MD010'           # Hard tabs
