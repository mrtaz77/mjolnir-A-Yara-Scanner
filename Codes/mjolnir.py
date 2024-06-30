from file_rules import FileRules

testRule = FileRules('test.yar')
testRule.match_file('matching_file.txt')