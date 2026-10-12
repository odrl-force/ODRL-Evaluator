export const RULES: string[] = [`@prefix : <http://example.org/> .
@prefix string: <http://www.w3.org/2000/10/swap/string#> .
@prefix log: <http://www.w3.org/2000/10/swap/log#> .
@prefix crypto: <http://www.w3.org/2000/10/swap/crypto#> .
@prefix list: <http://www.w3.org/2000/10/swap/list#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>.
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix : <http://example.org/> .
@prefix math: <http://www.w3.org/2000/10/swap/math#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix list: <http://www.w3.org/2000/10/swap/list#> .
@prefix log: <http://www.w3.org/2000/10/swap/log#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix temp: <http://example.com/request/> .
@prefix sotw: <https://w3id.org/force/sotw#> .
@prefix : <http://example.org/> .
@prefix math: <http://www.w3.org/2000/10/swap/math#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix list: <http://www.w3.org/2000/10/swap/list#> .
@prefix log: <http://www.w3.org/2000/10/swap/log#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#>.
@prefix sotw: <https://w3id.org/force/sotw#> .
@prefix cc: <http://creativecommons.org/ns#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix schema: <http://schema.org/> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix cc: <http://creativecommons.org/ns#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .

# uuid backward rule (component)
{
   ?input :getUUID ?urnUuid 
}
<= 
{
   # 0. add some skolem uri to introduce randomness when there are multiple runs with the same ID
  ( "test" ) log:skolem ?skolem .
  (?input (?skolem) ) list:append ?newList .
  
   # 1. Convert input to a stable string (log:skolem also works for blank nodes, log:uri does not)
   ?newList log:skolem ?skolemIRI .
   ?skolemIRI log:uri ?inputString .
   
   # 2. Generate a stable hash (works identically in 2026 eyeJS and Eyeling)
    ?inputString  crypto:sha ?hash .
   
   # 3. Format the hash into a UUID-compliant structure (8-4-4-4-12)
   ( ?hash "^(.{8}).*$" ) string:scrape ?p1 .
   ( ?hash "^.{8}(.{4}).*$" ) string:scrape ?p2 .
   ( ?hash "^.{12}(.{4}).*$" ) string:scrape ?p3 .
   ( ?hash "^.{16}(.{4}).*$" ) string:scrape ?p4 .
   ( ?hash "^.{20}(.{12}).*$" ) string:scrape ?p5 .
   ( "urn:uuid:" ?p1 "-" ?p2 "-" ?p3 "-" ?p4 "-" ?p5 ) string:concatenation ?urnUuidString .
   
   # 4. Cast the final string to a URI
   ?urnUuid log:uri ?urnUuidString .
} .

# 1. Base Case: An empty list results in an empty string
{ () :listToString "" } <= { } .

# 2. Recursive Case: Process list using rdf:first and rdf:rest
{ ?list :listToString ?result } <= {
    ?list rdf:first ?head .
    ?list rdf:rest ?tail .
    
    # Convert the current URI to a string
    ?head log:uri ?headStr .
    
    # Recursively convert the tail of the list
    ?tail :listToString ?tailStr .
    
    # Combine head and tail strings
    ( ?headStr ?tailStr ) string:concatenation ?result .
} .


# Evaluation request of a premise report, found by walking report:premiseReport links up to the rule report (any depth)
# NOTE: In the next iteration, the evaluation request will need to be retrieved from the policy. Also the policy report does contain this same timestamp
{ ?premiseReport :evaluationRequest ?evaluationRequest } <= {
    ?ruleReport report:ruleRequest ?evaluationRequest ;
        report:premiseReport ?premiseReport .
} .
{ ?premiseReport :evaluationRequest ?evaluationRequest } <= {
    ?parentReport report:premiseReport ?premiseReport .
    ?parentReport :evaluationRequest ?evaluationRequest .
} .

# Constraint report

# Connect constraint Report to Rule Report
{ 
    ?rule odrl:constraint ?constraint.
    ?ruleReport report:rule ?rule .
    ?premiseReport report:constraint ?constraint .
} => { 
    ?ruleReport report:premiseReport ?premiseReport .
}.

# Creates a premiseReport for each constraint there is (starting from a rule)
{
    _:a odrl:constraint ?constraint .
    ( ?constraint ) :getUUID ?premiseReport .

} => { 
    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint .
}.

# Creates a premiseReport for each constraint there is (starting from a logical operator)
{
    _:a ?logicaloperand ?constraint .
    ?logicaloperand list:in ( odrl:or odrl:xone odrl:and odrl:andSequence ) .

    ( ?constraint ) :getUUID ?premiseReport .
} => {
    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint .
} .
#######################################################################################################################
# Left Operand Conversion

# odrl:dateTime  from the evaluation request's temporal parameter
# https://www.w3.org/TR/odrl-vocab/#term-dateTime
{
    ?premiseReport report:constraint ?constraint ;
        :evaluationRequest ?evaluationRequest .

    ?constraint odrl:leftOperand odrl:dateTime .

    ?evaluationRequest sotw:requestParameter ?requestParam .
    ?requestParam sotw:describesFeature sotw:TemporalData ;
        sotw:value ?time .

    # TODO: check whether rightoperand is xsd:dateTime -> Not here; SHACL validation of constraints
    # Resolve when work in ODRL Validator for the resource track is finished        
} => {
    ?premiseReport report:constraintLeftOperand ?time .
}.

# odrl:purpose
# If the purpose is present in the evaluation request 
# NOTE: currently, this will match any purpose. This behaviour requires a proper fix
{ 
    ?premiseReport report:constraint ?constraint ;
        :evaluationRequest ?evaluationRequest . 

    ?constraint odrl:leftOperand odrl:purpose .

    # Purpose is provided by the related evaluation request (though this is optional)
    ?evaluationRequest sotw:requestParameter ?requestParam .
    ?requestParam sotw:describesFeature sotw:Purpose ;
        sotw:value ?purpose .
} => {
    ?premiseReport report:constraintLeftOperand ?purpose .
}.

# If no purpose is present in the evaluation request
{ 
    ?premiseReport report:constraint ?constraint ;
        :evaluationRequest ?evaluationRequest . 

    ?constraint odrl:leftOperand odrl:purpose .

    # Purpose is provided by the related evaluation request (though this is optional)
    (
        ?template
        {
            ?evaluationRequest sotw:requestParameter ?requestParam .
            ?requestParam sotw:describesFeature sotw:Purpose .
        }
        ?L
    ) log:collectAllIn ?SCOPE .
    # number of leftOperands in evaluation request is 1
    ?L list:length 0 .
} => {
    ?premiseReport report:constraintLeftOperand "" . #TODO: do we need a default null left operand value?
}.

# odrl:deliveryChannel
# If the delivery channel is present in the evaluation request 
# NOTE: currently, this will match any delivery channel. This behaviour requires a proper fix
{ 
    ?premiseReport report:constraint ?constraint ;
        :evaluationRequest ?evaluationRequest . 

    ?constraint odrl:leftOperand odrl:deliveryChannel .

    # A delivery channel is provided by the related evaluation request (though this is optional)
    ?evaluationRequest sotw:requestParameter ?requestParam .
    ?requestParam sotw:describesFeature sotw:DeliveryChannel ;
        sotw:value ?channel .
} => {
    ?premiseReport report:constraintLeftOperand ?channel .
}.

# If no delivery channel is present in the evaluation request
{ 
    ?premiseReport report:constraint ?constraint ;
        :evaluationRequest ?evaluationRequest . 

    ?constraint odrl:leftOperand odrl:deliveryChannel .

    # Purpose is provided by the related evaluation request (though this is optional)
    (
        ?template
        {
            ?evaluationRequest sotw:requestParameter ?requestParam .
            ?requestParam sotw:describesFeature sotw:DeliveryChannel .
        }
        ?L
    ) log:collectAllIn ?SCOPE .
    # number of leftOperands in evaluation request is 1
    ?L list:length 0 .
} => {
    ?premiseReport report:constraintLeftOperand "" . #TODO: do we need a default null left operand value?
}.

# Other ODRL constraint Left operands
# Create empty premise report for other odrl:leftOperands (no leftOperand present in the evaluation request)
{ 
    # acceptable ODRL Left Operands
    ?leftOperand list:in ( odrl:absolutePosition odrl:absoluteSize odrl:absoluteSpatialPosition odrl:absoluteTemporalPosition odrl:count odrl:delayPeriod odrl:device odrl:elapsedTime odrl:event odrl:fileFormat odrl:industry odrl:language odrl:media odrl:meteredTime odrl:payAmount odrl:percentage odrl:product odrl:recipient odrl:relativePosition odrl:relativeSize odrl:relativeSpatialPosition odrl:relativeTemporalPosition odrl:resolution odrl:spatial odrl:spatialCoordinates odrl:system odrl:systemDevice odrl:timeInterval odrl:unitOfCount odrl:version odrl:virtualLocation ) . 


    # a rule with a leftOperand constraint
    _:a odrl:constraint ?constraint .
    ?constraint odrl:leftOperand ?leftOperand .
    
    # created premiseReport
    ?premiseReport report:constraint ?constraint .
} => {
    ?premiseReport report:constraintLeftOperand "" . #TODO: do we need a default null left operand value?
}.

#######################################################################################################################
# Comparing the operators using the different odrl operators
# Ordered operators

# Less than: odrl:lt
{ 
    ?constraint 
        odrl:operator odrl:lt ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:lessThan ?rightOperand .

} =>
{
    ?premiseReport 
        report:constraintOperator odrl:lt ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .
# Greater than: odrl:gt
{ 
    ?constraint 
        odrl:operator odrl:gt ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:greaterThan ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:gt ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .

# Equal to: odrl:eq
# Recommendation by Jos on 03/10/2025: equality is difficult. Use both math:equalTo and log:equalTo
# OR operator does not exist in N3, so that's why you have to do it like this
# https://w3c.github.io/N3/reports/20230703/builtins.html#math:equalTo
{ 
    ?constraint 
        odrl:operator odrl:eq ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:equalTo ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:eq ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .

# https://w3c.github.io/N3/reports/20230703/builtins.html#log:equalTo
{ 
    ?constraint 
        odrl:operator odrl:eq ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand log:equalTo ?rightOperand .

} =>
{
    ?premiseReport 
        report:constraintOperator odrl:eq ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .

# Greater than or equal to: odrl:gteq
# https://w3c.github.io/N3/reports/20230703/builtins.html#math:notLessThan
{ 
    ?constraint 
        odrl:operator odrl:gteq ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:notLessThan ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:gteq ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .
# Less than or equal to: odrl:lteq
# https://w3c.github.io/N3/reports/20230703/builtins.html#math:notGreaterThan
{ 
    ?constraint 
        odrl:operator odrl:lteq ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:notGreaterThan ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:lteq ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .
# Not equal to: odrl:neq
# https://w3c.github.io/N3/reports/20230703/builtins.html#math:notEqualTo
{ 
    ?constraint 
        odrl:operator odrl:neq ;
        odrl:rightOperand ?rightOperand .

    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand math:notEqualTo ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:neq ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .

# Set-based Operators
# Is any of: odrl:isAnyOf
# There is a right operand value that equals the value that is actually present (through the sotw or evaluation request)
# https://w3c.github.io/N3/reports/20230703/builtins.html#log:equalTo
{
    ?constraint 
        odrl:operator odrl:isAnyOf ;
        odrl:rightOperand ?rightOperand .
    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .

    ?leftOperand log:equalTo ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:isAnyOf ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .
# Is an instance of: odrl:isA
{
    ?constraint 
        odrl:operator odrl:isA ;
        odrl:rightOperand ?rightOperand .
    
    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .
	?leftOperand a ?instance .
  
    ?instance log:equalTo ?rightOperand .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:isA ;
        report:constraintRightOperand ?rightOperand ;
        report:satisfactionState report:Satisfied .
} .
# Is none of: odrl:isNoneOf
{
    ?premiseReport a report:ConstraintReport ;
        report:constraint ?constraint ;
        report:constraintLeftOperand ?leftOperand .
    ?constraint odrl:operator odrl:isNoneOf .
    # Verify that there are no matches between the right operand value and the value that is actually present (through the sotw or evaluation request)
    (
        ?template
        {
        ?constraint odrl:rightOperand ?rightOperand .
        ?leftOperand log:equalTo ?rightOperand .
        }
        ?L
    ) log:collectAllIn ?SCOPE .
    ?L list:length 0 .
} =>
{
    ?premiseReport 
        report:constraintOperator odrl:isNoneOf ;
        report:satisfactionState report:Satisfied .
} .
# Make set-based reports complete by logging the remainder
{
    ?premiseReport report:constraintOperator ?operator ;
        report:constraint ?constraint .
    ?operator list:in ( odrl:isAnyOf odrl:isNoneOf) .
    ?constraint odrl:rightOperand ?rightOperand .
} => {
    ?premiseReport report:constraintRightOperand ?rightOperand .
} . 
#######################################################################################################################
# Logical operands
# logical operand premisereport generation
{ 
    # match and constraint
    ?constraint a odrl:LogicalConstraint;
       ?operandType ?otherConstraint .
    
    ?operandType list:in ( odrl:and odrl:or odrl:xone odrl:andSequence) .
    # create uuid
    ( ?constraint ) :getUUID ?logicalConstraintReportID .

    # I think the below rule might be troublesome in the future (with uc policies having reports themselves)

} => { 
    ?logicalConstraintReportID a report:ConstraintReport .
    ?logicalConstraintReportID report:constraint ?constraint .

    # Again, I don't think I can do it without explanation
    ?logicalConstraintReportID report:constraintLogicalOperand ?operandType .
}.

# connect logical operand constraints with other premise reports
{ 
    ?logicalConstraintReportID a report:ConstraintReport .
    ?logicalConstraintReportID report:constraint ?constraint .

    ?constraint ?operandType ?otherConstraint.
    ?operandType list:in ( odrl:and odrl:or odrl:xone odrl:andSequence) .

    ?otherConstraintReportID report:constraint ?otherConstraint.
} => {
    ?logicalConstraintReportID report:premiseReport ?otherConstraintReportID  .
} .

# Is and constraint report satisfied? (same for andsequence if you ask me)
{ 
    ?logicalConstraintReportID a report:ConstraintReport ;
        report:constraintLogicalOperand ?operandType .
    ?operandType list:in ( odrl:and odrl:andSequence) .

    
    # check for number of constraint reports
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport _:s 
        }
        ?L
    ) log:collectAllIn ?SCOPE .
    ?L list:length ?numberConstraints .

    # check for satisfied constraints
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport ?premiseReport .
            ?premiseReport report:satisfactionState report:Satisfied .
        }
        ?list
    ) log:collectAllIn ?SCOPE .
    ?list list:length ?satisfiedConstraints .
    ?satisfiedConstraints log:equalTo ?numberConstraints .  
    # TODO: when there are none satisfied, this is equal -> There is a need for other constraints to be unsatisfiable too (which is not the case yet) 
} => { 
    ?logicalConstraintReportID report:satisfactionState report:Satisfied  .

}.
{ 
    ?logicalConstraintReportID a report:ConstraintReport ;
        report:constraintLogicalOperand ?operandType .
    ?operandType list:in ( odrl:and odrl:andSequence) .
    
    # check for number of constraint reports
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport _:s 
        }
        ?L
    ) log:collectAllIn ?SCOPE .
    ?L list:length ?numberConstraints .

    # check for satisfied constraints
    (
        ?premiseReport
        {
            ?logicalConstraintReportID report:premiseReport ?premiseReport .
            ?premiseReport report:satisfactionState report:Satisfied .
        }
        ?list
    ) log:collectAllIn ?SCOPE .
    ?list list:length ?satisfiedConstraints .
    ?satisfiedConstraints log:notEqualTo ?numberConstraints .    
} => { 
    ?logicalConstraintReportID report:satisfactionState report:Unsatisfied  .
}.

# Is or constraint report satisfied?
{ 
    ?logicalConstraintReportID a report:ConstraintReport ;
        report:constraintLogicalOperand odrl:or .
    
    # check for satisfied constraints: At least on of them MUST be satisfied
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport ?premiseReport .
            ?premiseReport report:satisfactionState report:Satisfied .
        }
        ?list
    ) log:collectAllIn ?SCOPE .
    ?list list:length ?satisfiedConstraints .
    ?satisfiedConstraints math:notLessThan 1 .  
} => { 
    ?logicalConstraintReportID report:satisfactionState report:Satisfied  .

}.
{ 
    ?logicalConstraintReportID a report:ConstraintReport ;
        report:constraintLogicalOperand odrl:or .
    
    # check for satisfied constraints: At least on of them MUST be satisfied
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport ?premiseReport .
            ?premiseReport report:satisfactionState report:Satisfied .
        }
        ?list
    ) log:collectAllIn ?SCOPE .
    ?list list:length ?satisfiedConstraints .
    ?satisfiedConstraints log:equalTo 0 .  
} => { 
    ?logicalConstraintReportID report:satisfactionState report:Unsatisfied  .

}.
# is xone premise report satisfied? only one, and not more, of the Constraints MUST be satisfied
{ 
    ?logicalConstraintReportID a report:ConstraintReport ;
        report:constraintLogicalOperand odrl:xone .
    
    # check for satisfied constraints: At least on of them MUST be satisfied
    (
        ?template
        {
            ?logicalConstraintReportID report:premiseReport ?premiseReport .
            ?premiseReport report:satisfactionState report:Satisfied .
        }
        ?list
    ) log:collectAllIn ?SCOPE .
    ?list list:length ?satisfiedConstraints .
    ?satisfiedConstraints log:equalTo 1 .  
} => { 
    ?logicalConstraintReportID report:satisfactionState report:Satisfied  .

}.
#######################################################################################################################

# Policy report
{
   ?policy a ?policyType .
   ?policyType list:in ( odrl:Agreement odrl:Set odrl:Policy odrl:Offer ) .

   # Is there a valid request with time indication
   ?evaluationRequest a sotw:EvaluationRequest  ;
      sotw:requestParameter ?requestParam .
   ?requestParam sotw:describesFeature sotw:TemporalData ;
      sotw:value ?time .
   ( ?policy ) :getUUID ?urnUuid .
}
=> 
{
   ?urnUuid a report:PolicyReport ;
       dct:created ?time ;
       report:policy ?policy ;
       report:policyRequest ?evaluationRequest .
} .

# Permission report (expecting explicit permission type)
# create permission report
{
   ?policyReport a report:PolicyReport ;
       report:policy ?policy ;
       report:policyRequest ?evaluationRequest .
   ?policy odrl:permission ?permission .

   ( ?permission ) :getUUID ?urnUuid .
}
=> 
{
   ?policyReport report:ruleReport ?urnUuid .
   ?urnUuid a report:PermissionReport ;
       report:attemptState report:Attempted ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest .
} .

# Prohibition report (expecting explicit prohibition type)
# create prohibition report
{
   ?policyReport a report:PolicyReport ;
       report:policy ?policy ;
       report:policyRequest ?evaluationRequest .
   ?policy odrl:prohibition ?prohibition .

   ( ?prohibition ) :getUUID ?urnUuid .
}
=> 
{
   ?policyReport report:ruleReport ?urnUuid .
   ?urnUuid a report:ProhibitionReport ;
       report:attemptState report:Attempted ;
       report:rule ?prohibition ;
       report:ruleRequest ?evaluationRequest .
} .

# Target report
# Create target report from rule report if the ODRL rule has a target
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?rule .

   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .
   ?rule odrl:target ?resource .
   
   ( ?resource ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:TargetReport .
} .

# Calculate satisfaction state (simple asset)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?rule ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?targetReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

   ?targetReport a report:TargetReport .

   ?rule odrl:target ?resource .
   ?evaluationRequest sotw:evaluatedTarget ?requestedResource .

   ?resource log:equalTo ?requestedResource .

   # make sure not an asset collection
   (
      ?template
      {
         ?resource a odrl:AssetCollection .
      }
      ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?resourceCollectionsLength .
   ?resourceCollectionsLength log:equalTo 0 .
}
=> 
{
   ?targetReport report:satisfactionState report:Satisfied .
} .

# Calculate satisfaction state (asset collection)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?rule ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?targetReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

   ?targetReport a report:TargetReport .     
     
   ?rule odrl:target ?assetCollection .

   ?assetCollection a odrl:AssetCollection.

   ?evaluationRequest sotw:evaluatedTarget ?resourceInCollection .

   ?resourceInCollection odrl:partOf ?assetCollection .
}
=> 
{
   ?targetReport report:satisfactionState report:Satisfied .
} .

# Party report
# Create party report from rule report if the ODRL rule has an assignee
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission .
   ?permission odrl:assignee ?party .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

   ( ?party ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:PartyReport .
} .
# Calculate satisfaction state (simple party)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?partyReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .
   
   ?partyReport a report:PartyReport .

   ?permission odrl:assignee ?party .
   ?evaluationRequest sotw:evaluatedParty ?requestedParty .

   ?party log:equalTo ?requestedParty .
   
   # make sure not a party collection
      (
       ?template
       {
           ?party a odrl:PartyCollection .
       }
       ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?partyCollectionsLength .
   ?partyCollectionsLength log:equalTo 0 .
}
=> 
{
   ?partyReport report:satisfactionState report:Satisfied .
} .
# Calculate satisfaction state (party collection)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?partyReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .
   
   ?partyReport a report:PartyReport .

   ?permission odrl:assignee ?partyCollection .

   ?partyCollection a odrl:PartyCollection.

   ?evaluationRequest sotw:evaluatedParty ?requestedParty .

   ?requestedParty odrl:partOf ?partyCollection .
}
=> 
{
   ?partyReport report:satisfactionState report:Satisfied .
} .

# Action report 
# Create action report from rule report if the ODRL rule has an action
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission  .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

   ?permission odrl:action ?action .
   
   ( ?action ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:ActionReport .
} .
# Calculate satisfaction state (simple action)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?actionReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

   ?actionReport a report:ActionReport .
   ?permission odrl:action ?action .
   ?evaluationRequest sotw:evaluatedAction ?evaluatedAction .

   ?action log:equalTo ?evaluatedAction .
}
=> 
{
   ?actionReport a report:ActionReport ;
       report:satisfactionState report:Satisfied .
} .
# Calculate satisfaction state (included in)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?actionReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .
      
   ?actionReport a report:ActionReport .
   ?permission odrl:action ?action .
   ?evaluationRequest sotw:evaluatedAction ?evaluatedAction .

   ?evaluatedAction odrl:includedIn ?action .
} => 
{
   ?actionReport a report:ActionReport ;
       report:satisfactionState report:Satisfied .
} .
# Calculate satisfaction state (exact match)
{
   ?ruleReport a ?ruleReportType ;
       report:rule ?permission ;
       report:ruleRequest ?evaluationRequest ;
       report:premiseReport ?actionReport .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .
      
   ?actionReport a report:ActionReport .
   ?permission odrl:action ?action .
   ?evaluationRequest sotw:evaluatedAction ?evaluatedAction .

   ?evaluatedAction skos:exactMatch ?action .
} => 
{
   ?actionReport a report:ActionReport ;
       report:satisfactionState report:Satisfied .
} .

# ODRL Vocabulary
cc:Attribution a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attribution"@en ;
	skos:definition "Credit be given to copyright holder and/or author."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:CommercialUse a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Commercial Use"@en ;
	skos:definition "Exercising rights for commercial purposes."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:DerivativeWorks a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Derivative Works"@en ;
	skos:definition "Distribution of derivative works."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:Distribution a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Distribution"@en ;
	skos:definition "Distribution, public display, and publicly performance."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:Notice a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Notice"@en ;
	skos:definition "Copyright and license notices be kept intact."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:Reproduction a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Reproduction"@en ;
	skos:definition "Making multiple copies."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:ShareAlike a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Share Alike"@en ;
	skos:definition "Derivative works be licensed under the same terms or compatible terms as the original work."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:Sharing a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Sharing"@en ;
	skos:definition "Permits commercial derivatives, but only non-commercial distribution."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

cc:SourceCode a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Source Code"@en ;
	skos:definition "Source code (the preferred form for making modifications) must be provided when exercising some rights granted by the license."@en ;
	skos:note "This term is defined by Creative Commons."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

dcterms:contributor a owl:AnnotationProperty .

dcterms:creator a owl:AnnotationProperty .

dcterms:description a owl:AnnotationProperty .

dcterms:format a owl:AnnotationProperty .

dcterms:issued a owl:AnnotationProperty .

dcterms:isVersionOf a owl:AnnotationProperty .

dcterms:license a owl:AnnotationProperty .

dcterms:subject a owl:AnnotationProperty .

skos:broader a owl:AnnotationProperty .

skos:broaderTransitive a owl:AnnotationProperty .

skos:Collection a owl:Class .

skos:Concept a owl:Class .

skos:ConceptScheme a owl:Class .

skos:definition a owl:AnnotationProperty .

skos:hasTopConcept a owl:AnnotationProperty .

skos:member a owl:AnnotationProperty .

skos:note a owl:AnnotationProperty .

skos:prefLabel a owl:AnnotationProperty .

skos:scopeNote a owl:AnnotationProperty .

<http://www.w3.org/ns/odrl/2/> dcterms:contributor "W3C Permissions & Obligations Expression Working Group" ;
	dcterms:creator "Michael Steidl", "Renato Iannella", "Stuart Myles", "Víctor Rodríguez-Doncel" ;
	dcterms:description "The ODRL Vocabulary and Expression defines a set of concepts and terms (the vocabulary) and encoding mechanism (the expression) for permissions and obligations statements describing digital content usage based on the ODRL Information Model."@en ;
	dcterms:license <https://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231#Copyright/> ;
	a owl:Ontology ;
	rdfs:comment "This is the RDF ontology for ODRL Version 2.2."@en ;
	rdfs:label "ODRL Version 2.2"@en ;
	owl:versionInfo "2.2" .

<http://www.w3.org/ns/odrl/2/#actionConcepts> a skos:Collection ;
	skos:member odrl:action, odrl:Action, odrl:implies, odrl:includedIn ;
	skos:prefLabel "Action"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#actions> a skos:Collection ;
	skos:member odrl:transfer, odrl:use ;
	skos:prefLabel "Actions for Rules"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#actionsCommon> a skos:Collection ;
	skos:member cc:Attribution, cc:CommercialUse, cc:DerivativeWorks, cc:Distribution, cc:Notice, cc:Reproduction, cc:ShareAlike, cc:Sharing, cc:SourceCode, odrl:acceptTracking, odrl:aggregate, odrl:annotate, odrl:anonymize, odrl:archive, odrl:attribute, odrl:compensate, odrl:concurrentUse, odrl:delete, odrl:derive, odrl:digitize, odrl:display, odrl:distribute, odrl:ensureExclusivity, odrl:execute, odrl:extract, odrl:give, odrl:grantUse, odrl:include, odrl:index, odrl:inform, odrl:install, odrl:modify, odrl:move, odrl:nextPolicy, odrl:obtainConsent, odrl:play, odrl:present, odrl:print, odrl:read, odrl:reproduce, odrl:reviewPolicy, odrl:sell, odrl:stream, odrl:synchronize, odrl:textToSpeech, odrl:transform, odrl:translate, odrl:uninstall, odrl:watermark ;
	skos:prefLabel "Actions for Rules"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#assetConcepts> a skos:Collection ;
	skos:member odrl:Asset, odrl:AssetCollection ;
	skos:prefLabel "Asset"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#assetParty> a skos:Collection ;
	skos:member odrl:partOf, odrl:source ;
	skos:prefLabel "Asset and Party"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#assetRelations> a skos:Collection ;
	skos:member odrl:hasPolicy, odrl:target ;
	skos:prefLabel "Asset Relations"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#assetRelationsCommon> a skos:Collection ;
	skos:member odrl:output ;
	skos:prefLabel "Asset Relations"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#conflictConcepts> a skos:Collection ;
	skos:member odrl:conflict, odrl:ConflictTerm, odrl:invalid, odrl:perm, odrl:prohibit ;
	skos:prefLabel "Policy Conflict Strategy"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#constraintLeftOperandCommon> a skos:Collection ;
	skos:member odrl:absolutePosition, odrl:absoluteSize, odrl:absoluteSpatialPosition, odrl:absoluteTemporalPosition, odrl:count, odrl:dateTime, odrl:delayPeriod, odrl:deliveryChannel, odrl:elapsedTime, odrl:event, odrl:fileFormat, odrl:industry, odrl:language, odrl:media, odrl:meteredTime, odrl:payAmount, odrl:percentage, odrl:product, odrl:purpose, odrl:recipient, odrl:relativePosition, odrl:relativeSize, odrl:relativeSpatialPosition, odrl:relativeTemporalPosition, odrl:resolution, odrl:spatial, odrl:spatialCoordinates, odrl:systemDevice, odrl:timeInterval, odrl:unitOfCount, odrl:version, odrl:virtualLocation ;
	skos:prefLabel "Constraint Left Operands"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#constraintLogicalOperands> a skos:Collection ;
	skos:member odrl:and, odrl:andSequence, odrl:or, odrl:xone ;
	skos:prefLabel "Logical Constraint Operands"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#constraintRelationalOperators> a skos:Collection ;
	skos:member odrl:eq, odrl:gt, odrl:gteq, odrl:hasPart, odrl:isA, odrl:isAllOf, odrl:isAnyOf, odrl:isNoneOf, odrl:isPartOf, odrl:lt, odrl:lteq, odrl:neq ;
	skos:prefLabel "Constraint Operators"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#constraintRightOpCommon> a skos:Collection ;
	skos:member odrl:policyUsage ;
	skos:prefLabel "Constraint Right Operands"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#constraints> a skos:Collection ;
	skos:member odrl:constraint, odrl:Constraint, odrl:dataType, odrl:leftOperand, odrl:LeftOperand, odrl:operator, odrl:Operator, odrl:refinement, odrl:rightOperand, odrl:RightOperand, odrl:rightOperandReference, odrl:status, odrl:unit ;
	skos:prefLabel "Constraint"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#deprecatedTerms> a skos:Collection ;
	skos:member odrl:adHocShare, odrl:All, odrl:All2ndConnections, odrl:AllConnections, odrl:AllGroups, odrl:append, odrl:appendTo, odrl:AssetScope, odrl:attachPolicy, odrl:attachSource, odrl:commercialize, odrl:copy, odrl:device, odrl:export, odrl:extractChar, odrl:extractPage, odrl:extractWord, odrl:Group, odrl:ignore, odrl:Individual, odrl:inheritAllowed, odrl:inheritRelation, odrl:lease, odrl:lend, odrl:license, odrl:PartyScope, odrl:pay, odrl:payeeParty, odrl:preview, odrl:proximity, odrl:scope, odrl:secondaryUse, odrl:share, odrl:shareAlike, odrl:support, odrl:system, odrl:timedCount, odrl:undefined, odrl:UndefinedTerm, odrl:write, odrl:writeTo ;
	skos:prefLabel "Deprecated Terms"@en .

<http://www.w3.org/ns/odrl/2/#duties> a skos:Collection ;
	skos:member odrl:consequence, odrl:duty, odrl:Duty, odrl:obligation, odrl:remedy ;
	skos:prefLabel "Duty"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#logicalConstraints> a skos:Collection ;
	skos:member odrl:LogicalConstraint, odrl:operand ;
	skos:prefLabel "Logical Constraint"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#partyConcepts> a skos:Collection ;
	skos:member odrl:Party, odrl:PartyCollection ;
	skos:prefLabel "Party"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#partyRoles> a skos:Collection ;
	skos:member odrl:assignee, odrl:assigneeOf, odrl:assigner, odrl:assignerOf ;
	skos:prefLabel "Party Functions"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#partyRolesCommon> a skos:Collection ;
	skos:member odrl:attributedParty, odrl:attributingParty, odrl:compensatedParty, odrl:compensatingParty, odrl:consentedParty, odrl:consentingParty, odrl:contractedParty, odrl:contractingParty, odrl:informedParty, odrl:informingParty, odrl:trackedParty, odrl:trackingParty ;
	skos:prefLabel "Party Functions"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#permissions> a skos:Collection ;
	skos:member odrl:permission, odrl:Permission ;
	skos:prefLabel "Permission"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#policyConcepts> a skos:Collection ;
	skos:member odrl:inheritFrom, odrl:Policy, odrl:profile, odrl:uid ;
	skos:prefLabel "Policy"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#policySubClasses> a skos:Collection ;
	skos:member odrl:Agreement, odrl:Offer, odrl:Set ;
	skos:prefLabel "Policy Subclasses"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#policySubClassesCommon> a skos:Collection ;
	skos:member odrl:Assertion, odrl:Privacy, odrl:Request, odrl:Ticket ;
	skos:prefLabel "Policy Subclasses"@en ;
	skos:scopeNote "ODRL Common Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#prohibitions> a skos:Collection ;
	skos:member odrl:prohibition, odrl:Prohibition ;
	skos:prefLabel "Prohibition"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

<http://www.w3.org/ns/odrl/2/#ruleConcepts> a skos:Collection ;
	skos:member odrl:failure, odrl:function, odrl:relation, odrl:Rule ;
	skos:prefLabel "Rule"@en ;
	skos:scopeNote "ODRL Core Vocabulary Terms"@en .

odrl:absolutePosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Absolute Asset Position"@en ;
	skos:definition "A point in space or time defined with absolute coordinates for the positioning of the target Asset."@en ;
	skos:note "Example: The upper left corner of a picture may be constrained to a specific position of the canvas rendering it."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:absoluteSize a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Absolute Asset Size"@en ;
	skos:definition "Measure(s) of one or two axes for 2D-objects or measure(s) of one to tree axes for 3D-objects of the target Asset."@en ;
	skos:note "Example: The image can be resized in width to a maximum of 1000px."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:absoluteSpatialPosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Absolute Spatial Asset Position"@en ;
	skos:broaderTransitive odrl:absolutePosition ;
	skos:definition "The absolute spatial positions of four corners of a rectangle on a 2D-canvas or the eight corners of a cuboid in a 3D-space for the target Asset to fit."@en ;
	skos:note "Example: The upper left corner of a picture may be constrained to a specific position of the canvas rendering it. Note: see also the Left Operand Relative Spatial Asset Position. "@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:absoluteTemporalPosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Absolute Temporal Asset Position"@en ;
	skos:broaderTransitive odrl:absolutePosition ;
	skos:definition "The absolute temporal positions in a media stream the target Asset has to fit."@en ;
	skos:note "Use with Actions including the target Asset in a larger media stream. The fragment part of a Media Fragment URI (https://www.w3.org/TR/media-frags/) may be used for the right operand. See the Left Operand realativeTemporalPosition. <br />Example: The MP3 music file must be positioned between second 192 and 250 of the temporal length of a stream."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:acceptTracking a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Accept Tracking"@en ;
	skos:definition "To accept that the use of the Asset may be tracked."@en ;
	skos:note "The collected information may be tracked by the Assigner, or may link to a Party with the role 'trackingParty' function."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:action a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Action"@en ;
	rdfs:range odrl:Action ;
	skos:definition "The operation relating to the Asset for which the Rule is being subjected."@en .

odrl:Action a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Action"@en ;
	rdfs:subClassOf schema:Action ;
	skos:definition "An operation on an Asset."@en ;
	skos:note "Actions may be allowed by Permissions, disallowed by Prohibitions, or made mandatory by Duties."@en .

odrl:adHocShare a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Ad-hoc sharing"@en ;
	owl:deprecated true ;
	skos:definition "The act of sharing the asset to parties in close proximity to the owner."@en ;
	skos:note "This original term and URI from the OMA specification should be used: http://www.openmobilealliance.com/oma-dd/adhoc-share ."@en .

odrl:aggregate a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Aggregate"@en ;
	skos:definition "To use the Asset or parts of it as part of a composite collection."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Agreement a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Agreement"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Assertion, odrl:Offer, odrl:Privacy, odrl:Request, odrl:Ticket ;
	skos:definition "A Policy that grants the assignee a Rule over an Asset from an assigner."@en ;
	skos:note "An Agreement Policy MUST contain at least one Permission or Prohibition rule, a Party with Assigner function, and a Party with Assignee function (in the same Permission or Prohibition). The Agreement Policy will grant the terms of the Policy from the Assigner to the Assignee."@en .

odrl:All a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "All"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is all of the collective individuals within a context."@en ;
	skos:note "For example, may be used to indicate all the users of a specific social network the party is a member of. Note that “group” scope is also assumed."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:All2ndConnections a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "All Second-level Connections"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is all of the second-level connections to the Party."@en ;
	skos:note "For example, may be used to indicate all “friends of friends” of the Party. Note that “group” scope is also assumed."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:AllConnections a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "All First-Level Connections"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is all of the first-level connections of the Party."@en ;
	skos:note "For example, may be used to indicate all “friends” of the Party. Note that “group” scope is also assumed."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:AllGroups a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "All Group Connections"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is all of the group connections of the Party."@en ;
	skos:note "For example, may be used to indicate all groups that the Party is a member of. Note that “group” scope is also assumed."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:and a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "And"@en ;
	rdfs:subPropertyOf odrl:operand ;
	skos:definition "The relation is satisfied when all of the Constraints are satisfied."@en ;
	skos:note "This property MUST only be used for Logical Constraints, and the list of operand values MUST be Constraint instances."@en .

odrl:andSequence a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "And Sequence"@en ;
	rdfs:subPropertyOf odrl:operand ;
	skos:definition "The relation is satisfied when each of the Constraints are satisfied in the order specified."@en ;
	skos:note "This property MUST only be used for Logical Constraints, and the list of operand values MUST be Constraint instances. The order of the list MUST be preserved. The andSequence operator is an example where there may be temporal conditional requirements between the operands. This may lead to situations where the outcome is unresolvable, such as deadlock if one of the Constraints is unable to be satisfied. ODRL Processing systems SHOULD plan for these scenarios and implement mechanisms to resolve them."@en .

odrl:annotate a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Annotate"@en ;
	skos:definition "To add explanatory notations/commentaries to the Asset without modifying the Asset in any other way."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:anonymize a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Anonymize"@en ;
	skos:definition "To anonymize all or parts of the Asset."@en ;
	skos:note "For example, to remove identifying particulars for statistical or for other comparable purposes, or to use the Asset without stating the author/source."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:append a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Append"@en ;
	owl:deprecated true ;
	skos:definition "The act of adding to the end of an asset."@en ;
	skos:exactMatch odrl:modify .

odrl:appendTo a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Append To"@en ;
	owl:deprecated true ;
	skos:definition "The act of appending data to the Asset without modifying the Asset in any other way."@en ;
	skos:exactMatch odrl:modify .

odrl:archive a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Archive"@en ;
	skos:definition "To store the Asset (in a non-transient form)."@en ;
	skos:note "Temporal constraints may be used for temporal conditions."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Assertion a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Assertion"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Offer, odrl:Privacy, odrl:Request, odrl:Ticket ;
	skos:definition "A Policy that asserts a Rule over an Asset from parties."@en ;
	skos:note "For example, a party (an assignee or assigner) can claim what terms they have over an Asset. An Assertion Policy does not grant such permissions/prohibitions but only asserts the parties claims. An Assetion Policy MUST contain a target Asset, a Party with any functional role, and at least one of a Permission or Prohibition rule."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:Asset a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Asset"@en ;
	skos:definition "A resource or a collection of resources that are the subject of a Rule."@en ;
	skos:note "The Asset entity can be any form of identifiable resource, such as data/information, content/media, applications, or services. Furthermore, it can be used to represent other Asset entities that are needed to undertake the Policy expression, such as with the Duty entity. To describe more details about the Asset, it is recommended to use Dublin Core [[dcterms]] elements or other content metadata."@en .

odrl:AssetCollection a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Asset Collection"@en ;
	rdfs:subClassOf odrl:Asset ;
	skos:definition "An Asset that is collection of individual resources"@en .

odrl:AssetScope a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Asset Scope"@en ;
	owl:deprecated true ;
	skos:definition "Scopes for Asset Scope expressions."@en ;
	skos:note "Instances of the AssetScope class represent the terms for the scope property of Assets."@en .

odrl:assignee a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Assignee"@en ;
	rdfs:range odrl:Party ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party is the recipient of the Rule."@en .

odrl:assigneeOf a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Party ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Assignee Of"@en ;
	rdfs:range odrl:Policy ;
	skos:definition "Identifies an ODRL Policy for which the identified Party undertakes the assignee functional role."@en ;
	skos:note "When assigneeOf has been asserted between a metadata expression and an ODRL Policy, the Party being identified MUST be inferred to undertake the assignee functional role of all the Rules of that Policy."@en .

odrl:assigner a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Assigner"@en ;
	rdfs:range odrl:Party ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party is the issuer of the Rule."@en .

odrl:assignerOf a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Party ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Assigner Of"@en ;
	rdfs:range odrl:Policy ;
	skos:definition "Identifies an ODRL Policy for which the identified Party undertakes the assigner functional role."@en ;
	skos:note "When assignerOf has been asserted between a metadata expression and an ODRL Policy, the Party being identified MUST be inferred to undertake the assigner functional role of all the Rules of that Policy."@en .

odrl:attachPolicy a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attach policy"@en ;
	owl:deprecated true ;
	skos:definition "The act of keeping the policy notice with the asset."@en ;
	skos:exactMatch cc:Notice .

odrl:attachSource a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attach source"@en ;
	owl:deprecated true ;
	skos:definition "The act of attaching the source of the asset and its derivatives."@en ;
	skos:exactMatch cc:SourceCode .

odrl:attribute a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attribute"@en ;
	skos:definition "To attribute the use of the Asset."@en ;
	skos:note "May link to an Asset with the attribution information. May link to a Party with the role “attributedParty” function."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:attributedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attributed Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party to be attributed."@en ;
	skos:note "Maybe specified as part of the attribute action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:attributingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Attributing Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who undertakes the attribution."@en ;
	skos:note "Maybe specified as part of the attribute action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:commercialize a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Commercialize"@en ;
	owl:deprecated true ;
	skos:definition "The act of using the asset in a business environment."@en ;
	skos:exactMatch cc:CommercialUse .

odrl:compensate a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Compensate"@en ;
	skos:definition "To compensate by transfer of some amount of value, if defined, for using or selling the Asset."@en ;
	skos:note "The compensation may use different types of things with a value: (i) the thing is expressed by the value (term) of the Constraint name; (b) the value is expressed by operator, rightOperand, dataType and unit. Typically the assignee will compensate the assigner, but other compensation party roles may be used."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:compensatedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Compensated Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party is the recipient of the compensation."@en ;
	skos:note "Maybe specified as part of the compensate duty action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:compensatingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Compensating Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party that is the provider of the compensation."@en ;
	skos:note "Maybe specified as part of the compensate duty action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:concurrentUse a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Concurrent Use"@en ;
	skos:definition "To create multiple copies of the Asset that are being concurrently used."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:conflict a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Handle Policy Conflicts"@en ;
	rdfs:range odrl:ConflictTerm ;
	skos:definition "The conflict-resolution strategy for a Policy."@en ;
	skos:note "If no strategy is specified, the default is invalid."@en .

odrl:ConflictTerm a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Conflict Strategy Preference"@en ;
	skos:definition "Used to establish strategies to resolve conflicts that arise from the merging of Policies or conflicts between Permissions and Prohibitions in the same Policy."@en ;
	skos:note "Instances of ConflictTerm describe strategies for resolving conflicts."@en .

odrl:consentedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Consented Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who obtains the consent."@en ;
	skos:note "Maybe specified as part of the obtainConsent action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:consentingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Consenting Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party to obtain consent from."@en ;
	skos:note "Maybe specified as part of the obtainConsent action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:consequence a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Duty ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Consequence"@en ;
	rdfs:range odrl:Duty ;
	rdfs:subPropertyOf odrl:failure ;
	skos:definition "Relates a Duty to another Duty, the latter being a consequence of not fulfilling the former."@en ;
	skos:note "The consequence property is utilised to express the repercussions of not fulfilling an agreed Policy obligation or duty for a Permission. If either of these fails to be fulfilled, then this will result in the consequence Duty also becoming a new requirement, meaning that the original obligation or duty, as well as the consequence Duty must all be fulfilled"@en .

odrl:constraint a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Policy
			odrl:Rule
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Constraint"@en ;
	rdfs:range [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Constraint
			odrl:LogicalConstraint
		) ;
	] ;
	skos:definition "Constraint applied to a Rule"@en ;
	skos:note "Constraints on Rules are used to determine if a rule is Active or not. Example: the Permission rule is only active during the year 2018."@en .

odrl:Constraint a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Constraint"@en ;
	skos:definition "A boolean expression that refines the semantics of an Action and Party/Asset Collection or declare the conditions applicable to a Rule."@en .

odrl:contractedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Contracted Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who is being contracted."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:contractingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Contracting Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who is offering the contract."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:copy a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Copy"@en ;
	owl:deprecated true ;
	owl:sameAs odrl:reproduce ;
	skos:definition "The act of making an exact reproduction of the asset."@en ;
	skos:exactMatch odrl:reproduce .

odrl:core a owl:Thing, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "ODRL Core Profile"@en ;
	skos:definition "Identifier for the ODRL Core Profile"@en .

odrl:count a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Count"@en ;
	skos:definition "Numeric count of executions of the action of the Rule."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:dataType a rdf:Property, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Datatype"@en ;
	rdfs:range rdfs:Datatype ;
	skos:definition "The datatype of the value of the rightOperand or rightOperandReference of a Constraint."@en ;
	skos:note "In RDF encodings, use of the rdf:datatype MUST be used. In JSON-LD encoding, the use of @type MUST be used."@en .

odrl:dateTime a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Datetime"@en ;
	skos:definition "The date (and optional time and timezone) of exercising the action of the Rule. Right operand value MUST be an xsd:date or xsd:dateTime as defined by [[xmlschema11-2]]."@en ;
	skos:note "The use of Timezone information is strongly recommended. The Rule may be exercised before (with operator lt/lteq) or after (with operator gt/gteq) the date(time) defined by the Right operand. <br />Example: <code>dateTime gteq 2017-12-31T06:00Z</code> means the Rule can only be exercised after (and including) 6:00AM on the 31st Decemeber 2017 UTC time."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:delayPeriod a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Delay Period"@en ;
	skos:definition "A time delay period prior to exercising the action of the Rule. The point in time triggering this period MAY be defined by another temporal Constraint combined by a Logical Constraint (utilising the odrl:andSequence operand). Right operand value MUST be an xsd:duration as defined by [[xmlschema11-2]]."@en ;
	skos:note "Only the eq, gt, gteq operators SHOULD be used. <br />Example: <code>delayPeriod eq P60M</code> indicates a delay of 60 Minutes before exercising the action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:delete a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Delete"@en ;
	skos:definition "To permanently remove all copies of the Asset after it has been used."@en ;
	skos:note "Use a constraint to define under which conditions the Asset must be deleted."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:deliveryChannel a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Delivery Channel"@en ;
	skos:definition "The delivery channel used for exercising the action of the Rule."@en ;
	skos:note "Example: the asset may be distributed only on mobile networks."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:derive a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Derive"@en ;
	skos:definition "To create a new derivative Asset from this Asset and to edit or modify the derivative."@en ;
	skos:note "A new asset is created and may have significant overlaps with the original Asset. (Note that the notion of whether or not the change is significant enough to qualify as a new asset is subjective). To the derived Asset a next policy may be applied."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:device a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Device"@en ;
	owl:deprecated true ;
	skos:definition "An identified device used for exercising the action of the Rule."@en ;
	skos:exactMatch odrl:systemDevice ;
	skos:note "See System Device." .

odrl:digitize a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Digitize"@en ;
	skos:definition "To produce a digital copy of (or otherwise digitize) the Asset from its analogue form."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:display a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Display"@en ;
	skos:definition "To create a static and transient rendition of an Asset."@en ;
	skos:note "For example, displaying an image on a screen. If the action is to be performed to a wider audience than just the Assignees, then the Recipient constraint is recommended to be used."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:play .

odrl:distribute a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Distribute"@en ;
	skos:definition "To supply the Asset to third-parties."@en ;
	skos:note "It is recommended to use nextPolicy to express the allowable usages by third-parties."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:duty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Permission ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Duty"@en ;
	rdfs:range odrl:Duty ;
	skos:definition "Relates an individual Duty to a Permission."@en ;
	skos:note "A Duty is a pre-condition which must be fulfilled in order to receive the Permission."@en .

odrl:Duty a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Duty"@en ;
	rdfs:subClassOf odrl:Rule ;
	owl:disjointWith odrl:Permission, odrl:Prohibition ;
	skos:definition "The obligation to perform an Action"@en .

odrl:elapsedTime a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Elapsed Time"@en ;
	skos:definition "A continuous elapsed time period which may be used for exercising of the action of the Rule. Right operand value MUST be an xsd:duration as defined by [[xmlschema11-2]]."@en ;
	skos:note "Only the eq, lt, lteq operators SHOULD be used. See also Metered Time. <br />Example: <code>elpasedTime eq P60M</code> indicates a total elapsed time of 60 Minutes." ;
	skos:scopeNote "Non-Normative"@en .

odrl:ensureExclusivity a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Ensure Exclusivity"@en ;
	skos:definition "To ensure that the Rule on the Asset is exclusive."@en ;
	skos:note "If used as a Duty, the assignee should be explicitly indicated as the party that is ensuring the exclusivity of the Rule."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:eq a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Equal to"@en ;
	skos:definition "Indicating that a given value equals the right operand of the Constraint."@en .

odrl:event a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Event"@en ;
	skos:definition "An identified event setting a context for exercising the action of the Rule."@en ;
	skos:note "Events are temporal periods of time, and operators can be used to signal before (lt), during (eq) or after (gt) the event. <br />Example: May be taken during the “FIFA World Cup 2020” only."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:execute a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Execute"@en ;
	skos:definition "To run the computer program Asset."@en ;
	skos:note "For example, machine executable code or Java such as a game or application."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:export a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Export"@en ;
	owl:deprecated true ;
	skos:definition "The act of transforming the asset into a new form."@en ;
	skos:exactMatch odrl:transform .

odrl:extract a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Extract"@en ;
	skos:definition "To extract parts of the Asset and to use it as a new Asset."@en ;
	skos:note "A new asset is created and may have very little in common with the original Asset. (Note that the notion of whether or not the change is significant enough to qualify as a new asset is subjective). To the extracted Asset a next policy may be applied."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:reproduce .

odrl:extractChar a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Extract character"@en ;
	owl:deprecated true ;
	skos:definition "The act of extracting (replicating) unchanged characters from the asset."@en ;
	skos:note "This original term and URI from the ONIX specification should be used: http://www.editeur.org/onix-pl/extract-char ."@en .

odrl:extractPage a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Extract page"@en ;
	owl:deprecated true ;
	skos:definition "The act of extracting (replicating) unchanged pages from the asset."@en ;
	skos:note "This original term and URI from the ONIX specification should be used: http://www.editeur.org/onix-pl/extract-page ."@en .

odrl:extractWord a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Extract word"@en ;
	owl:deprecated true ;
	skos:definition "The act of extracting (replicating) unchanged words from the asset."@en ;
	skos:note "This original term and URI from the ONIX specification should be used: http://www.editeur.org/onix-pl/extract-word ."@en .

odrl:failure a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Rule ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Failure"@en ;
	rdfs:range odrl:Rule ;
	skos:definition "Failure is an abstract property that defines the violation (or unmet) relationship between Rules."@en ;
	skos:note "The parent property to sub-properties that express explicit failure contexts."@en .

odrl:fileFormat a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "File Format"@en ;
	skos:definition "A transformed file format of the target Asset."@en ;
	skos:note "Example: An asset may be transformed into JPEG format."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:function a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Function"@en ;
	rdfs:range odrl:Party ;
	skos:definition "Function is an abstract property whose sub-properties define the functional roles which may be fulfilled by a party in relation to a Rule."@en .

odrl:give a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Give"@en ;
	skos:definition "To transfer the ownership of the Asset to a third party without compensation and while deleting the original asset."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:transfer .

odrl:grantUse a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Grant Use"@en ;
	skos:definition "To grant the use of the Asset to third parties."@en ;
	skos:note "This action enables the assignee to create policies for the use of the Asset for third parties. The nextPolicy is recommended to be agreed with the third party. Use of temporal constraints is recommended."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Group a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Group"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is the defined group with multiple individual members."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:gt a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Greater than"@en ;
	skos:definition "Indicating that a given value is greater than the right operand of the Constraint."@en .

odrl:gteq a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Greater than or equal to"@en ;
	skos:definition "Indicating that a given value is greater than or equal to the right operand of the Constraint."@en .

odrl:hasPart a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has part"@en ;
	skos:definition "A set-based operator indicating that a given value contains the right operand of the Constraint."@en .

odrl:hasPolicy a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Asset ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Target Policy"@en ;
	rdfs:range odrl:Policy ;
	skos:definition "Identifies an ODRL Policy for which the identified Asset is the target Asset to all the Rules."@en ;
	skos:note "The Asset being identified MUST be inferred to be the target Asset of all of the Rules of the Policy."@en .

odrl:ignore a owl:NamedIndividual, skos:Concept, odrl:UndefinedTerm ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Ignore Undefined Actions"@en ;
	owl:deprecated true ;
	skos:definition "The Action is to be ignored and is not part of the policy – and the policy remains valid."@en ;
	skos:note "Used to support actions not known to the policy system."@en .

odrl:implies a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Implies"@en ;
	rdfs:range odrl:Action ;
	skos:definition "An Action asserts that another Action is not prohibited to enable its operational semantics."@en ;
	skos:note "The property asserts that an instance of Action entails that the other instance of Action is not prohibited."@en .

odrl:include a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Include"@en ;
	skos:definition "To include other related assets in the Asset."@en ;
	skos:note "For example: bio picture must be included in the attribution. Use of a relation sub-property is required for the related assets."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:includedIn a rdf:Property, owl:ObjectProperty, owl:TransitiveProperty, skos:Concept ;
	rdfs:domain odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Included In"@en ;
	rdfs:range odrl:Action ;
	skos:definition "An Action transitively asserts that another Action that encompasses its operational semantics."@en ;
	skos:note "The purpose is to explicitly assert that the semantics of the referenced instance of an other Action encompasses (includes) the semantics of this instance of Action. The includedIn property is transitive, and as such, the Actions form ancestor relationships."@en .

odrl:index a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Index"@en ;
	skos:definition "To record the Asset in an index."@en ;
	skos:note "For example, to include a link to the Asset in a search engine database."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Individual a owl:NamedIndividual, skos:Concept, odrl:PartyScope ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Individual"@en ;
	owl:deprecated true ;
	skos:definition "Specifies that the scope of the relationship is the single Party individual."@en .

odrl:industry a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Industry Context"@en ;
	skos:definition "A defined industry sector setting a context for exercising the action of the Rule."@en ;
	skos:note "Example: publishing or financial industry."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:inform a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Inform"@en ;
	skos:definition "To inform that an action has been performed on or in relation to the Asset."@en ;
	skos:note "May link to a Party with the role 'informedParty' function."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:informedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Informed Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party to be informed of all uses."@en ;
	skos:note "Maybe specified as part of the inform action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:informingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Informing Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who provides the inform use data."@en ;
	skos:note "Maybe specified as part of the inform action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:inheritAllowed a rdf:Property, owl:DatatypeProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Inheritance Allowed"@en ;
	owl:deprecated true ;
	skos:definition "Indicates if the Policy entity can be inherited."@en ;
	skos:note "A boolean value."@en .

odrl:inheritFrom a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Inherits From"@en ;
	rdfs:range odrl:Policy ;
	skos:definition "Relates a (child) policy to another (parent) policy from which terms are inherited."@en ;
	skos:note "The child policy will inherit Rules from the parent policy"@en .

odrl:inheritRelation a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Inherit Relation"@en ;
	owl:deprecated true ;
	skos:definition "Indentifies the type of inheritance."@en ;
	skos:note "For example, this may indicate the business scenario, such as subscription, or prior arrangements between the parties (that are not machine representable)."@en .

odrl:install a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Install"@en ;
	skos:definition "To load the computer program Asset onto a storage device which allows operating or running the Asset."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:invalid a owl:NamedIndividual, skos:Concept, odrl:ConflictTerm ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Void Policy"@en ;
	skos:definition "The policy is void."@en ;
	skos:note "Used to indicate the policy is void for Conflict Strategy."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:isA a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Is a"@en ;
	skos:definition "A set-based operator indicating that a given value is an instance of the right operand of the Constraint."@en .

odrl:isAllOf a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Is all of"@en ;
	skos:definition "A set-based operator indicating that a given value is all of the right operand of the Constraint."@en .

odrl:isAnyOf a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Is any of"@en ;
	skos:definition "A set-based operator indicating that a given value is any of the right operand of the Constraint."@en .

odrl:isNoneOf a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Is none of"@en ;
	skos:definition "A set-based operator indicating that a given value is none of the right operand of the Constraint."@en .

odrl:isPartOf a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Is part of"@en ;
	skos:definition "A set-based operator indicating that a given value is contained by the right operand of the Constraint."@en .

odrl:language a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Language"@en ;
	skos:definition "A natural language used by the target Asset."@en ;
	skos:note "Example: the asset can only be translated into Greek. Must use [[bcp47]] codes for language values."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:lease a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Lease"@en ;
	owl:deprecated true ;
	skos:definition "The act of making available the asset to a third-party for a fixed period of time with exchange of value."@en .

odrl:leftOperand a rdf:Property, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Left Operand"@en ;
	rdfs:range odrl:LeftOperand ;
	skos:definition "The left operand in a constraint expression."@en .

odrl:LeftOperand a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Left Operand"@en ;
	skos:definition "Left operand for a constraint expression."@en ;
	skos:note "Instances of the LeftOperand class are used as the leftOperand of a Constraint."@en .

odrl:lend a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Lend"@en ;
	owl:deprecated true ;
	skos:definition "The act of making available the asset to a third-party for a fixed period of time without exchange of value."@en .

odrl:license a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "License"@en ;
	owl:deprecated true ;
	skos:definition "The act of granting the right to use the asset to a third-party."@en ;
	skos:exactMatch odrl:grantUse .

odrl:LogicalConstraint a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Logical Constraint"@en ;
	skos:definition "A logical expression that refines the semantics of an Action and Party/Asset Collection or declare the conditions applicable to a Rule."@en .

odrl:lt a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Less than"@en ;
	skos:definition "Indicating that a given value is less than the right operand of the Constraint."@en .

odrl:lteq a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Less than or equal to"@en ;
	skos:definition "Indicating that a given value is less than or equal to the right operand of the Constraint."@en .

odrl:media a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Media Context"@en ;
	skos:definition "Category of a media asset setting a context for exercising the action of the Rule."@en ;
	skos:note "Example media types: electronic, print, advertising, marketing. Note: The used type should not be an IANA MediaType as they are focused on technical characteristics. "@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:meteredTime a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Metered Time"@en ;
	skos:definition "An accumulated amount of one to many metered time periods which were used for exercising the action of the Rule. Right operand value MUST be an xsd:duration as defined by [[xmlschema11-2]]."@en ;
	skos:note "Only the eq, lt, lteq operators SHOULD be used. See also Elapsed Time. <br />Example: <code>meteredTime lteq P60M</code> indicates an accumulated period of 60 Minutes or less." ;
	skos:scopeNote "Non-Normative"@en .

odrl:modify a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Modify"@en ;
	skos:definition "To change existing content of the Asset. A new asset is not created by this action."@en ;
	skos:note "This action will modify an asset which is typically updated from time to time without creating a new asset. If the result from modifying the asset should be a new asset the actions derive or extract should be used. (Note that the notion of whether or not the change is significant enough to qualify as a new asset is subjective)."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:move a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Move"@en ;
	skos:definition "To move the Asset from one digital location to another including deleting the original copy."@en ;
	skos:note "After the Asset has been moved, the original copy must be deleted."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:neq a owl:NamedIndividual, skos:Concept, odrl:Operator ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Not equal to"@en ;
	skos:definition "Indicating that a given value is not equal to the right operand of the Constraint."@en .

odrl:nextPolicy a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Next Policy"@en ;
	skos:definition "To grant the specified Policy to a third party for their use of the Asset."@en ;
	skos:note "Useful for downstream policies."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:obligation a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Obligation"@en ;
	rdfs:range odrl:Duty ;
	skos:definition "Relates an individual Duty to a Policy."@en ;
	skos:note "The Duty is a requirement which must be fulfilled."@en .

odrl:obtainConsent a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Obtain Consent"@en ;
	skos:definition "To obtain verifiable consent to perform the requested action in relation to the Asset."@en ;
	skos:note "May be used as a Duty to ensure that the Assigner or a Party is authorized to approve such actions on a case-by-case basis. May link to a Party with the role “consentingParty” function."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Offer a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Offer"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Agreement, odrl:Assertion, odrl:Privacy, odrl:Request, odrl:Ticket ;
	skos:definition "A Policy that proposes a Rule over an Asset from an assigner."@en ;
	skos:note "An Offer Policy MUST contain at least one Permission or Prohibition rule and a Party with Assigner function (in the same Permission or Prohibition). The Offer Policy MAY contain a Party with Assignee function, but MUST not grant any privileges to that Party."@en .

odrl:operand a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:LogicalConstraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Operand"@en ;
	skos:definition "Operand is an abstract property for a logical relationship."@en ;
	skos:note "Sub-properties of operand are used for Logical Constraints."@en .

odrl:operator a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Operator"@en ;
	rdfs:range odrl:Operator ;
	skos:definition "The operator function applied to operands of a Constraint"@en .

odrl:Operator a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Operator"@en ;
	skos:definition "Operator for constraint expression."@en ;
	skos:note "Instances of the Operator class representing relational operators."@en .

odrl:or a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Or"@en ;
	rdfs:subPropertyOf odrl:operand ;
	skos:definition "The relation is satisfied when at least one of the Constraints is satisfied."@en ;
	skos:note "This property MUST only be used for Logical Constraints, and the list of operand values MUST be Constraint instances."@en .

odrl:output a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Rule ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Output"@en ;
	rdfs:range odrl:Asset ;
	rdfs:subPropertyOf odrl:relation ;
	skos:definition "The output property specifies the Asset which is created from the output of the Action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:partOf a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Asset
			odrl:Party
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Part Of"@en ;
	rdfs:range [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:AssetCollection
			odrl:PartyCollection
		) ;
	] ;
	skos:definition "Identifies an Asset/PartyCollection that the Asset/Party is a member of."@en .

odrl:Party a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Party"@en ;
	rdfs:subClassOf [
		rdf:type owl:Class ;
		owl:unionOf (
			schema:Person
			schema:Organization
			foaf:Person
			foaf:Organization
			foaf:Agent
			vcard:Individual
			vcard:Organization
			vcard:Agent
		) ;
	] ;
	skos:definition "An entity or a collection of entities that undertake Roles in a Rule."@en ;
	skos:note "The Party entity could be a person, group of people, organisation, or agent. An agent is a person or thing that takes an active role or produces a specified effect. To describe more details about the Party, it is recommended to use W3C vCard Ontology [[vcard-rdf]] or FOAF Vocabulary [[foaf]]."@en .

odrl:PartyCollection a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Party Collection"@en ;
	rdfs:subClassOf odrl:Party ;
	skos:definition "A Party that is a group of individual entities"@en .

odrl:PartyScope a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Party Scope"@en ;
	owl:deprecated true ;
	skos:definition "Scopes for Party Scope expressions."@en ;
	skos:note "Instances of the PartyScope class represent the terms for the scope property of Parties."@en .

odrl:pay a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Pay"@en ;
	owl:deprecated true ;
	skos:definition "The act of paying a financial amount to a party for use of the asset."@en ;
	skos:exactMatch odrl:compensate .

odrl:payAmount a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Payment Amount"@en ;
	skos:definition "The amount of a financial payment. Right operand value MUST be an xsd:decimal. "@en ;
	skos:note "Can be used for compensation duties with the unit property indicating the currency of the payment."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:payeeParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Payee Party"@en ;
	owl:deprecated true ;
	skos:definition "The Party is the recipient of the payment."@en ;
	skos:exactMatch odrl:compensatedParty ;
	skos:scopeNote "Non-Normative"@en .

odrl:percentage a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Asset Percentage"@en ;
	skos:definition "A percentage amount of the target Asset relevant for exercising the action of the Rule. Right operand value MUST be an xsd:decimal from 0 to 100."@en ;
	skos:note "Example: Extract less than or equal to 50%."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:perm a owl:NamedIndividual, skos:Concept, odrl:ConflictTerm ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Prefer Permissions"@en ;
	skos:definition "Permissions take preference over prohibitions."@en ;
	skos:note "Used to determine policy conflict outcomes."@en .

odrl:permission a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Permission"@en ;
	rdfs:range odrl:Permission ;
	skos:definition "Relates an individual Permission to a Policy."@en .

odrl:Permission a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Permission"@en ;
	rdfs:subClassOf odrl:Rule ;
	owl:disjointWith odrl:Duty, odrl:Prohibition ;
	skos:definition "The ability to perform an Action over an Asset."@en .

odrl:play a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Play"@en ;
	skos:definition "To create a sequential and transient rendition of an Asset."@en ;
	skos:note "For example, to play a video or audio track. If the action is to be performed to a wider audience than just the Assignees, then the Recipient constraint is recommended to be used." ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Policy a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Policy"@en ;
	skos:definition "A non-empty group of Permissions and/or Prohibitions."@en ;
	skos:note "A Policy may contain multiple Rules."@en .

odrl:policyUsage a owl:NamedIndividual, skos:Concept, odrl:RightOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Policy Rule Usage"@en ;
	skos:definition "Indicates the actual datetime the action of the Rule was exercised."@en ;
	skos:note "This can be used to express constraints with a LeftOperand relative to the time the rule is exercised. Operators indicate before (lt, lteq), during (eq) or after (gt, gteq) the usage of the rule. <br />Example: <code>event lt policyUsage</code> expresses that the identified event must have happened before the action of the rule is exercised."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:present a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Present"@en ;
	skos:definition "To publicly perform the Asset."@en ;
	skos:note "The asset can be performed (or communicated) in public." ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:preview a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Preview"@en ;
	owl:deprecated true ;
	skos:definition "The act of providing a short preview of the asset."@en ;
	skos:note "Use a time constraint with the appropriate action."@en .

odrl:print a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Print"@en ;
	skos:definition "To create a tangible and permanent rendition of an Asset."@en ;
	skos:note "For example, creating a permanent, fixed (static), and directly perceivable representation of the Asset, such as printing onto paper."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Privacy a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Privacy Policy"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Agreement, odrl:Assertion, odrl:Offer, odrl:Request, odrl:Ticket ;
	skos:definition "A Policy that expresses a Rule over an Asset containing personal information."@en ;
	skos:note "A Privacy Policy MUST contain a target Asset, a Party with Assigner is, a Party with Assignee function, and at least one of a Permission or Prohibition rule that MUST include a Duty. The target Asset SHOULD contain or relate to personal information about the Assignee. The Duty MUST describe obligations on the Assigner about managing the Asset. The Assignee is being granted the terms of the Privacy policy from the Assigner."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:product a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Product Context"@en ;
	skos:definition "Category of product or service setting a context for exercising the action of the Rule."@en ;
	skos:note "Example: May only be used in the XYZ Magazine."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:profile a rdf:Property, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Profile"@en ;
	skos:definition "The identifier(s) of an ODRL Profile that the Policy conforms to."@en ;
	skos:note "The profile property is mandatory if the Policy is using an ODRL Profile."@en .

odrl:prohibit a owl:NamedIndividual, skos:Concept, odrl:ConflictTerm ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Prefer Prohibitions"@en ;
	skos:definition "Prohibitions take preference over permissions."@en ;
	skos:note "Used to determine policy conflict outcomes."@en .

odrl:prohibition a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Policy ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Prohibition"@en ;
	rdfs:range odrl:Prohibition ;
	skos:definition "Relates an individual Prohibition to a Policy."@en .

odrl:Prohibition a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Prohibition"@en ;
	rdfs:subClassOf odrl:Rule ;
	owl:disjointWith odrl:Duty, odrl:Permission ;
	skos:definition "The inability to perform an Action over an Asset."@en .

odrl:proximity a rdf:Property, owl:DatatypeProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "proximity"@en ;
	owl:deprecated true ;
	skos:definition "An value indicating the closeness or nearness."@en ;
	skos:note "This original term and URI from the OMA specification should be used: http://www.openmobilealliance.com/oma-dd/proximity ."@en .

odrl:purpose a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Purpose"@en ;
	skos:definition "A defined purpose for exercising the action of the Rule."@en ;
	skos:note "Example: Educational use."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:read a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Read"@en ;
	skos:definition "To obtain data from the Asset."@en ;
	skos:note "For example, the ability to read a record from a database (the Asset)."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:recipient a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Recipient"@en ;
	skos:definition "The party receiving the result/outcome of exercising the action of the Rule."@en ;
	skos:note "The Right Operand must identify one or more specific Parties or category/ies of the Party."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:refinement a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Action
			odrl:AssetCollection
			odrl:PartyCollection
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Refinement"@en ;
	rdfs:range [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Constraint
			odrl:LogicalConstraint
		) ;
	] ;
	skos:definition "Constraint used to refine the semantics of an Action, or Party/Asset Collection"@en ;
	skos:note "Example: the Action print is only permitted on 50% of the asset."@en .

odrl:relation a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Relation"@en ;
	rdfs:range odrl:Asset ;
	skos:definition "Relation is an abstract property which creates an explicit link between an Action and an Asset."@en ;
	skos:note "Sub-properties of relation are used to define the nature of that link."@en .

odrl:relativePosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Relative Asset Position"@en ;
	skos:definition "A point in space or time defined with coordinates relative to full measures the positioning of the target Asset."@en ;
	skos:note "Example: The upper left corner of a picture may be constrained to a specific position of the canvas rendering it."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:relativeSize a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Relative Asset Size"@en ;
	skos:definition "Measure(s) of one or two axes for 2D-objects or measure(s) of one to tree axes for 3D-objects - expressed as percentages of full values - of the target Asset."@en ;
	skos:note "Example: The image can be resized in width to a maximum of 200%. Note: See the Left Operand absoluteSize. "@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:relativeSpatialPosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Relative Spatial Asset Position"@en ;
	skos:broaderTransitive odrl:relativePosition ;
	skos:definition "The relative spatial positions - expressed as percentages of full values - of four corners of a rectangle on a 2D-canvas or the eight corners of a cuboid in a 3D-space of the target Asset."@en ;
	skos:note "See also Absolute Spatial Asset Position."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:relativeTemporalPosition a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Relative Temporal Asset Position"@en ;
	skos:broaderTransitive odrl:relativePosition ;
	skos:definition "A point in space or time defined with coordinates relative to full measures the positioning of the target Asset."@en ;
	skos:note "See also Absolute Temporal Asset Position. <br />Example: The MP3 music file must be positioned between the positions at 33% and 48% of the temporal length of a stream. "@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:remedy a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain odrl:Prohibition ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Remedy"@en ;
	rdfs:range odrl:Duty ;
	rdfs:subPropertyOf odrl:failure ;
	skos:definition "Relates an individual remedy Duty to a Prohibition."@en ;
	skos:note "The remedy property expresses an agreed Duty that must be fulfilled in case that a Prohibition has been violated by being exercised."@en .

odrl:reproduce a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Reproduce"@en ;
	skos:definition "To make duplicate copies the Asset in any material form."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Request a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Request"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Agreement, odrl:Assertion, odrl:Offer, odrl:Privacy, odrl:Ticket ;
	skos:definition "A Policy that proposes a Rule over an Asset from an assignee."@en ;
	skos:note "A Request Policy MUST contain a target Asset, a Party with Assignee function, and at least one of a Permission or Prohibition rule. The Request MAY also contain the Party with Assigner function if this is known. No privileges are granted to any Party."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:resolution a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Rendition Resolution"@en ;
	skos:definition "Resolution of the rendition of the target Asset."@en ;
	skos:note "Example: the image may be printed at 1200dpi."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:reviewPolicy a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Review Policy"@en ;
	skos:definition "To review the Policy applicable to the Asset."@en ;
	skos:note "Used when human intervention is required to review the Policy. May link to an Asset which represents the full Policy information."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:rightOperand a rdf:Property, owl:DatatypeProperty, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Right Operand"@en ;
	rdfs:range [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:RightOperand
			rdfs:Literal
			xsd:anyURI
		) ;
	] ;
	skos:definition "The value of the right operand in a constraint expression."@en ;
	skos:note "When used with set-based operators, a list of values may be used."@en .

odrl:RightOperand a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Right Operand"@en ;
	skos:definition "Right operand for constraint expression."@en ;
	skos:note "Instances of the RightOperand class are used as the rightOperand of a Constraint."@en .

odrl:rightOperandReference a rdf:Property, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Has Right Operand Reference"@en ;
	skos:definition "A reference to a web resource providing the value for the right operand of a Constraint."@en ;
	skos:note "An IRI that MUST be dereferenced to obtain the actual right operand value. When used with set-based operators, a list of IRIs may be used"@en .

odrl:Rule a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Rule"@en ;
	skos:definition "An abstract concept that represents the common characteristics of Permissions, Prohibitions, and Duties."@en ;
	skos:note "Rule is an abstract concept."@en .

odrl:scope a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Scope"@en ;
	owl:deprecated true ;
	skos:definition "The identifier of a scope that provides context to the extent of the entity."@en ;
	skos:note "Used to define scopes for Assets and Parties."@en .

odrl:secondaryUse a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Secondary Use"@en ;
	owl:deprecated true ;
	skos:definition "The act of using the asset for a purpose other than the purpose it was intended for."@en .

odrl:sell a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Sell"@en ;
	skos:definition "To transfer the ownership of the Asset to a third party with compensation and while deleting the original asset."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:transfer .

odrl:Set a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Set"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Agreement, odrl:Assertion, odrl:Offer, odrl:Privacy, odrl:Request, odrl:Ticket ;
	skos:definition "A Policy that expresses a Rule over an Asset."@en ;
	skos:note "A Set Policy MUST contain a target Asset, and at least one Rule. A Set Policy is the default Policy subclass. The Set is aimed at scenarios where there is an open criteria for the semantics of the policy expressions and typically refined by other systems/profiles that process the information at a later time. No privileges are granted to any Party (if defined)."@en .

odrl:share a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Share"@en ;
	owl:deprecated true ;
	skos:definition "The act of the non-commercial reproduction and distribution of the asset to third-parties."@en ;
	skos:exactMatch cc:Sharing .

odrl:shareAlike a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Share-alike"@en ;
	owl:deprecated true ;
	skos:definition "The act of distributing any derivative asset under the same terms as the original asset."@en ;
	skos:exactMatch cc:ShareAlike .

odrl:source a rdf:Property, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:AssetCollection
			odrl:PartyCollection
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Source"@en ;
	skos:definition "Reference to a Asset/PartyCollection"@en ;
	skos:note "Used by AssetCollection and PartyCollection when constraints are applied."@en .

odrl:spatial a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Geospatial Named Area"@en ;
	skos:definition "A named and identified geospatial area with defined borders which is used for exercising the action of the Rule. An IRI MUST be used to represent this value."@en ;
	skos:note "A code value for the area and source of the code must be presented in the Right Operand. <br />Example: the [[iso3166]] Country Codes or the Getty Thesaurus of Geographic Names. "@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:spatialCoordinates a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Geospatial Coordinates"@en ;
	skos:broaderTransitive odrl:spatial ;
	skos:definition "A set of coordinates setting the borders of a geospatial area used for exercising the action of the Rule. The coordinates MUST include longitude and latitude, they MAY include altitude and the geodetic datum."@en ;
	skos:note "The default values are the altitude of earth's surface at this location and the WGS 84 datum."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:status a rdf:Property, skos:Concept ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Status"@en ;
	skos:definition "the value generated from the leftOperand action or a value related to the leftOperand set as the reference for the comparison."@en .

odrl:stream a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Stream"@en ;
	skos:definition "To deliver the Asset in real-time."@en ;
	skos:note "The Asset maybe utilised in real-time as it is being delivered. If the action is to be performed to a wider audience than just the Assignees, then the Recipient constraint is recommended to be used." ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:support a owl:NamedIndividual, skos:Concept, odrl:UndefinedTerm ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Support Undefined Actions"@en ;
	owl:deprecated true ;
	skos:definition "The Action is to be supported as part of the policy – and the policy remains valid."@en ;
	skos:note "Used to support actions not known to the policy system."@en .

odrl:synchronize a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Synchronize"@en ;
	skos:definition "To use the Asset in timed relations with media (audio/visual) elements of another Asset."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:system a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "System"@en ;
	owl:deprecated true ;
	skos:definition "An identified computing system used for exercising the action of the Rule."@en ;
	skos:exactMatch odrl:systemDevice ;
	skos:note "See System Device" .

odrl:systemDevice a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "System Device"@en ;
	skos:definition "An identified computing system or computing device used for exercising the action of the Rule."@en ;
	skos:exactMatch odrl:device, odrl:system ;
	skos:note "Example: The system device can be identified by a unique code created from the used hardware."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:target a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Rule
			odrl:Policy
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Target"@en ;
	rdfs:range odrl:Asset ;
	rdfs:subPropertyOf odrl:relation ;
	skos:definition "The target property indicates the Asset that is the primary subject to which the Rule action directly applies."@en .

odrl:textToSpeech a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Text-to-speech"@en ;
	skos:definition "To have a text Asset read out loud."@en ;
	skos:note "If the action is to be performed to a wider audience than just the Assignees, then the recipient constraint is recommended to be used." ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:Ticket a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Ticket"@en ;
	rdfs:subClassOf odrl:Policy ;
	owl:disjointWith odrl:Agreement, odrl:Assertion, odrl:Offer, odrl:Privacy, odrl:Request ;
	skos:definition "A Policy that grants the holder a Rule over an Asset from an assigner."@en ;
	skos:note "A Ticket Policy MUST contain a target Asset and at least one of a Permission or Prohibition rule. The Ticket MAY contain the Party with Assigner function and MUST NOT contain an Assignee. The Ticket Policy will grant the terms of the Policy to the holder of that Ticket. The holder of the Ticket MAY remain unknown or MAY have to be identified at some later stage."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:timedCount a rdf:Property, owl:DatatypeProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Timed Count"@en ;
	rdfs:range rdfs:Literal ;
	owl:deprecated true ;
	skos:definition "The number of seconds after which timed metering use of the asset begins."@en ;
	skos:note "This original term and URI from the OMA specification should be used: http://www.openmobilealliance.com/oma-dd/timed-count ."@en .

odrl:timeInterval a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Recurring Time Interval"@en ;
	skos:definition "A recurring period of time before the next execution of the action of the Rule. Right operand value MUST be an xsd:duration as defined by [[xmlschema11-2]]."@en ;
	skos:note "Only the eq operator SHOULD be used. <br />Example: <code>timeInterval eq P7D</code> indicates a recurring 7 day period." ;
	skos:scopeNote "Non-Normative"@en .

odrl:trackedParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Tracked Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party whose usage is being tracked."@en ;
	skos:note "May be specified as part of the acceptTracking action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:trackingParty a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Tracking Party"@en ;
	rdfs:subPropertyOf odrl:function ;
	skos:definition "The Party who is tracking usage."@en ;
	skos:note "May be specified as part of the acceptTracking action."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:transfer a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Transfer Ownership"@en ;
	skos:definition "To transfer the ownership of the Asset in perpetuity."@en .

odrl:transform a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Transform"@en ;
	skos:definition "To convert the Asset into a different format."@en ;
	skos:note "Typically used to convert the Asset into a different format for consumption on/transfer to a third party system."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:translate a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Translate"@en ;
	skos:definition "To translate the original natural language of an Asset into another natural language."@en ;
	skos:note "A new derivative Asset is created by that action."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:uid a rdf:Property, skos:Concept ;
	rdfs:domain [
		rdf:type owl:Class ;
		owl:unionOf (
			odrl:Policy
			odrl:Asset
			odrl:Rule
			odrl:Party
			odrl:Constraint
			odrl:LogicalConstraint
		) ;
	] ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Unique Identifier"@en ;
	skos:definition "An unambiguous identifier"@en ;
	skos:note "Used by the Policy, Rule, Asset, Party, Constraint, and Logical Constraint Classes."@en .

odrl:undefined a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Handle Undefined Term"@en ;
	rdfs:range odrl:UndefinedTerm ;
	owl:deprecated true ;
	skos:definition "Relates the strategy used for handling undefined actions to a Policy."@en ;
	skos:note "If no strategy is specified, the default is invalid."@en .

odrl:UndefinedTerm a rdfs:Class, owl:Class, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Undefined Term"@en ;
	owl:deprecated true ;
	skos:definition "Is used to indicate how to support Actions that are not part of any vocabulary or profile in the policy expression system."@en ;
	skos:note "Instances of UndefinedTerm describe strategies for processing unsupported actions."@en .

odrl:uninstall a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Uninstall"@en ;
	skos:definition "To unload and delete the computer program Asset from a storage device and disable its readiness for operation."@en ;
	skos:note "The Asset is no longer accessible to the assignees after it has been used."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:unit a rdf:Property ;
	rdfs:domain odrl:Constraint ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Unit"@en ;
	skos:definition "The unit of measurement of the value of the rightOperand or rightOperandReference of a Constraint."@en .

odrl:unitOfCount a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Unit Of Count"@en ;
	skos:definition "The unit of measure used for counting the executions of the action of the Rule."@en ;
	skos:note "Note: Typically used with Duties to indicate the unit entity to be counted of the Action. <br />Example: A duty to compensate and a unitOfCount constraint of 'perUser' would indicate that the compensation by multiplied by the 'number of users'."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:use a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Use"@en ;
	skos:definition "To use the Asset"@en ;
	skos:note "Use is the most generic action for all non-third-party usage. More specific types of the use action can be expressed by more targetted actions."@en .

odrl:version a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Version"@en ;
	skos:definition "The version of the target Asset."@en ;
	skos:note "Example: Single Paperback or Multiple Issues or version 2.0 or higher."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:virtualLocation a owl:NamedIndividual, skos:Concept, odrl:LeftOperand ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Virtual IT Communication Location"@en ;
	skos:definition "An identified location of the IT communication space which is relevant for exercising the action of the Rule."@en ;
	skos:note "Example: an Internet domain or IP address range."@en ;
	skos:scopeNote "Non-Normative"@en .

odrl:watermark a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Watermark"@en ;
	skos:definition "To apply a watermark to the Asset."@en ;
	skos:scopeNote "Non-Normative"@en ;
	odrl:includedIn odrl:use .

odrl:write a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Write"@en ;
	owl:deprecated true ;
	skos:definition "The act of writing to the Asset."@en ;
	skos:exactMatch odrl:modify .

odrl:writeTo a skos:Concept, odrl:Action ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Write to"@en ;
	owl:deprecated true ;
	skos:definition "The act of adding data to the Asset."@en ;
	skos:exactMatch odrl:modify .

odrl:xone a rdf:Property, owl:ObjectProperty, skos:Concept ;
	rdfs:isDefinedBy <http://www.w3.org/ns/odrl/2/> ;
	rdfs:label "Only One"@en ;
	rdfs:subPropertyOf odrl:operand ;
	skos:definition "The relation is satisfied when only one, and not more, of the Constaints is satisfied"@en ;
	skos:note "This property MUST only be used for Logical Constraints, and the list of operand values MUST be Constraint instances."@en .



# Inferences about exact match cached (also contains symmetric property "odrl:includedIn")
odrl:modify skos:exactMatch odrl:append.
odrl:modify skos:exactMatch odrl:appendTo.
cc:Notice skos:exactMatch odrl:attachPolicy.
cc:SourceCode skos:exactMatch odrl:attachSource.
cc:CommercialUse skos:exactMatch odrl:commercialize.
odrl:reproduce skos:exactMatch odrl:copy.
odrl:transform skos:exactMatch odrl:export.
odrl:grantUse skos:exactMatch odrl:license.
odrl:compensate skos:exactMatch odrl:pay.
odrl:compensatedParty skos:exactMatch odrl:payeeParty.
cc:Sharing skos:exactMatch odrl:share.
cc:ShareAlike skos:exactMatch odrl:shareAlike.
odrl:modify skos:exactMatch odrl:write.
odrl:modify skos:exactMatch odrl:writeTo.
odrl:append odrl:includedIn odrl:use.
odrl:appendTo odrl:includedIn odrl:use.
odrl:attachPolicy odrl:includedIn odrl:use.
odrl:attachSource odrl:includedIn odrl:use.
odrl:commercialize odrl:includedIn odrl:use.
odrl:copy odrl:includedIn odrl:use.
odrl:export odrl:includedIn odrl:use.
odrl:license odrl:includedIn odrl:use.
odrl:pay odrl:includedIn odrl:use.
odrl:share odrl:includedIn odrl:use.
odrl:shareAlike odrl:includedIn odrl:use.
odrl:write odrl:includedIn odrl:use.
odrl:writeTo odrl:includedIn odrl:use.
odrl:display odrl:includedIn odrl:use.
odrl:extract odrl:includedIn odrl:use.`, `@prefix : <http://example.org/> .
@prefix list: <http://www.w3.org/2000/10/swap/list#> .
@prefix log: <http://www.w3.org/2000/10/swap/log#> .
@prefix report: <https://w3id.org/force/compliance-report#> .

# check whether rule report is active
{
   ?ruleReport a ?ruleReportType ;
       report:attemptState report:Attempted ;
       report:rule ?rule ;
       report:ruleRequest ?evaluationRequest .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

    # check for number of constraint reports
   (
       ?template
       {
           ?ruleReport report:premiseReport _:s 
       }
       ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?numberConstraints .

    # check for satisfied constraints
   (
       ?premiseReport
       {
           ?ruleReport report:premiseReport ?premiseReport .
           ?premiseReport report:satisfactionState report:Satisfied .
       }
       ?list
   ) log:collectAllIn ?SCOPE .
   ?list list:length ?satisfiedConstraints .
   ?satisfiedConstraints log:equalTo ?numberConstraints .
}
=> 
{
   ?ruleReport report:activationState report:Active .
} .
{
   ?ruleReport a ?ruleReportType ;
       report:attemptState report:Attempted ;
       report:rule ?rule ;
       report:ruleRequest ?evaluationRequest .
   ?ruleReportType list:in (report:PermissionReport report:RuleReport report:ProhibitionReport) .

    # check for number of constraint reports
   (
       ?template
       {
           ?ruleReport report:premiseReport _:s 
       }
       ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?numberConstraints .

    # check for satisfied constraints
   (
       ?premiseReport
       {
           ?ruleReport report:premiseReport ?premiseReport .
           ?premiseReport report:satisfactionState report:Satisfied .
       }
       ?list
   ) log:collectAllIn ?SCOPE .
   ?list list:length ?satisfiedConstraints .
   ?satisfiedConstraints log:notEqualTo ?numberConstraints .
}
=> 
{
   ?ruleReport report:activationState report:Inactive .
} .

# If premise reports don't have a satisfaction status -> they are unsatisfied
{ 
    ?report a ?premiseReport .
    ?premiseReport list:in (report:TargetReport report:ConstraintReport report:PartyReport report:ActionReport ) .
    (
      ?template
      {
         ?report report:satisfactionState  _:s .
      }
      ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?satisfactionStateLength .
   ?satisfactionStateLength log:equalTo 0 .
} =>
{
    ?report report:satisfactionState report:Unsatisfied .
} .`];
export const SIMPLE_RULES: string[] = [`@prefix : <http://example.org/> .
@prefix math: <http://www.w3.org/2000/10/swap/math#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix list: <http://www.w3.org/2000/10/swap/list#> .
@prefix log: <http://www.w3.org/2000/10/swap/log#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix string: <http://www.w3.org/2000/10/swap/string#> .
@prefix temp: <http://example.com/request/> .

# uuid backward rule (component)
{
   ?input :getUUID ?urnUuid 
}
<= 
{
   ?input log:skolem ?uniqueNode .
   ?uniqueNode log:uuid ?uuidString .
   ( "urn:uuid:" ?uuidString ) string:concatenation ?urnUuidString .
   ?urnUuid log:uri ?urnUuidString .
} .

# Policy report
{
   ?policy a ?policyType .
   ?policyType list:in ( odrl:Agreement odrl:Set odrl:Policy odrl:Offer ) .
   ?policyRequest a odrl:Request .
   temp:currentTime dct:issued ?time .
   ( ?policy ) :getUUID ?urnUuid .
}
=> 
{
   ?urnUuid a report:PolicyReport ;
       dct:created ?time ;
       report:policy ?policy ;
       report:policyRequest ?policyRequest .
} .

# Permission report (expecting explicit permission type)
# create permission report
{
   ?policyReport a report:PolicyReport ;
       report:policy ?policy ;
       report:policyRequest ?policyRequest .
   ?policy odrl:permission ?permission .
   ?policyRequest odrl:permission ?requestPermission .
   ( ?permission ) :getUUID ?urnUuid .
}
=> 
{
   ?policyReport report:ruleReport ?urnUuid .
   ?urnUuid a report:PermissionReport ;
       report:attemptState report:Attempted ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
} .

# check whether permission report is active
{
   ?urnUuid a report:PermissionReport ;
       report:attemptState report:Attempted ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .

    # check for number of constraint reports
   (
       ?template
       {
           ?urnUuid report:premiseReport _:s 
       }
       ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?numberConstraints .

    # check for satisfied constraints
   (
       ?premiseReport
       {
           ?urnUuid report:premiseReport ?premiseReport .
           ?premiseReport report:satisfactionState report:Satisfied .
       }
       ?list
   ) log:collectAllIn ?SCOPE .
   ?list list:length ?satisfiedConstraints .
   ?satisfiedConstraints log:equalTo ?numberConstraints .
}
=> 
{
   ?urnUuid report:activationState report:Active .
} .
{
   ?urnUuid a report:PermissionReport ;
       report:attemptState report:Attempted ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .

    # check for number of constraint reports
   (
       ?template
       {
           ?urnUuid report:premiseReport _:s 
       }
       ?L
   ) log:collectAllIn ?SCOPE .
   ?L list:length ?numberConstraints .

    # check for satisfied constraints
   (
       ?premiseReport
       {
           ?urnUuid report:premiseReport ?premiseReport .
           ?premiseReport report:satisfactionState report:Satisfied .
       }
       ?list
   ) log:collectAllIn ?SCOPE .
   ?list list:length ?satisfiedConstraints .
   ?satisfiedConstraints log:notEqualTo ?numberConstraints .
}
=> 
{
   ?urnUuid report:activationState report:Inactive .
} .


# Constraint report

# Target report
{
   ?ruleReport a report:PermissionReport ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
   ?permission odrl:target ?resource .
   ?requestPermission odrl:target ?requestedResource .
   ?resource log:equalTo ?requestedResource .
   ( ?resource ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:TargetReport ;
       report:satisfactionState report:Satisfied .
} .
# Party report
{
   ?ruleReport a report:PermissionReport ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
   ?permission odrl:assignee ?party .
   ?requestPermission odrl:assignee ?requestedParty .
   ?party log:equalTo ?requestedParty .
   ( ?party ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:PartyReport ;
       report:satisfactionState report:Satisfied .
} .
{
   ?ruleReport a report:PermissionReport ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
   ?permission odrl:assignee ?party .
   ?requestPermission odrl:assignee ?requestedParty .
   ?party log:notEqualTo ?requestedParty .
   ( ?party ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:PartyReport ;
       report:satisfactionState report:Unsatisfied .
} .
# Action report -> simple action
{
   ?ruleReport a report:PermissionReport ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
   ?permission odrl:action ?action .
   ?requestPermission odrl:action ?requestedAction .
   ?action log:equalTo ?requestedAction .
   ( ?action ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:ActionReport ;
       report:satisfactionState report:Satisfied .
} .
{
   ?ruleReport a report:PermissionReport ;
       report:rule ?permission ;
       report:ruleRequest ?requestPermission .
   ?permission odrl:action ?action .
   ?requestPermission odrl:action ?requestedAction .
   ?action log:notEqualTo ?requestedAction .
   ( ?action ) :getUUID ?urnUuid .
}
=> 
{
   ?ruleReport report:premiseReport ?urnUuid .
   ?urnUuid a report:ActionReport ;
       report:satisfactionState report:Unsatisfied .
} .
`];