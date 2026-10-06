import type { Quad } from '@rdfjs/types';
import { Store } from 'n3';
import { Normalizer } from "odrl-validator/dist/Normalisation";
import { EyelingReasoner } from '../reasoner/EyelingReasoner';
import { Reasoner } from '../reasoner/Reasoner';
import { RULES } from '../rules/Rules';
import { mergeDerivedRuleReports } from '../util/NormalizationUtil';
import { ODRL, RDF, SOTW } from '../util/Vocabularies';
import { materializePolicy } from './DynamicConstraint';
import { Engine, ODRLEngine, ODRLEngineMultipleSteps } from './Engine';
import { RDFValidator, SHACLValidator, TripleTermValidator, Validator } from './Validate';
export interface Evaluator {
    /**
     * Based on a set of policies, a formal description of the world,
     * and, in the case of access control, an access control,
     * determine whether the usage of data was and is permitted 
     * and whether all obligations have been met.
     * 
     * @param policy - A Usage Control Policy (represented in RDF).
     * @param request - An Access Control Request (represented in RDF).
     * @param state - The state of the world (represented in RDF).
     * @returns A conformance report
     */
    evaluate: (policy: Quad[], request: Quad[], state: Quad[]) => Promise<Quad[]>;
}

export type EvaluatorInput = {
    reasoner?: Reasoner, // general purpose Notation 3 Reasoner
    ODRLValidator?: Validator<Quad[], boolean>, // checks whether the ODRL policy is valid. If not given does not reason
    // Currently, will always use the ODRL multiple run engine, so we do not allow options.
    // This gives an issue if we want to allow another rule set
    inputValidation?: boolean // checks whether there is at least one policy and exactly one state of the world
    instantiation?: boolean // performs the instantiation introduced in Interoperable and Continuous Usage Control Enforcement in Dataspaces (https://ceur-ws.org/Vol-3705/paper10.pdf)
    normalisation?: boolean // performs ODRL Normalization
}

const DEFAULTS = {
    inputValidation: true,
    instantiation: false,
    normalisation: false,
} as const;
export class ODRLEvaluatorV2 implements Evaluator {
    private readonly engine: Engine
    private readonly reasoner: Reasoner;
    private readonly normaliser: Normalizer;

    private readonly odrlValidator?: Validator<Quad[], boolean>;   // stays undefined => does not validate the ODRL policies
    private readonly inputValidation: boolean;
    private readonly instantiation: boolean;
    private readonly normalisation: boolean;
    private readonly odrlValidation: boolean;

    constructor(config: EvaluatorInput = {}) {
        const {
            reasoner = new EyelingReasoner(),            // lazily constructed only when absent
            ODRLValidator,                               // no default on purpose
            inputValidation = DEFAULTS.inputValidation,
            instantiation = DEFAULTS.instantiation,
            normalisation = DEFAULTS.normalisation,
        } = config;
        this.odrlValidator = ODRLValidator;
        this.reasoner = reasoner;
        this.engine = new ODRLEngineMultipleSteps({ reasoner, rules: RULES })
        this.normaliser = new Normalizer();

        this.inputValidation = inputValidation;
        this.instantiation = instantiation;
        this.normalisation = normalisation;
        this.odrlValidation = this.odrlValidator !== undefined
    }

    public async evaluate(policy: Quad[], request: Quad[], state: Quad[]): Promise<Quad[]> {
        let policyStore = new Store(policy)
        const sotwStore = new Store(state)
        
        // validation
        if (this.inputValidation) {
            validateInput(policy, state);
            // TODO: add a check that there is a max of one evaluation request?
        }

        if (this.odrlValidation && !(await this.odrlValidator.validate(policy))) {
            throw new Error("One of the ODRL policies is not valid.");
            // TODO: make Shacl validator use the ODRL validator
        }

        // preprocess
        let normalized = policy;
        if (this.normalisation) {
            normalized = await this.normaliser.normalise(policy);
        }

        let prepared = normalized;
        if (this.instantiation) {
            prepared = materializePolicy(normalized, state);
        }

        // evaluate
        let evaluation = await this.engine.evaluate([...prepared, ...request, ...state]);

        // postprocess
        if (this.normalisation) {
            evaluation = mergeDerivedRuleReports(evaluation, normalized);
        }

        return evaluation
    }

}
export function validateInput(policy: Quad[], state: Quad[]): void {
    const policyStore = new Store(policy);
    // NOTE: this might be a problem later with profiles. But the Evaluator rules only contain Agreement, Set, Policy and Offer
    const hasPolicy = [ODRL.Policy, ODRL.Agreement, ODRL.Set, ODRL.Offer]
        .some(type => policyStore.countQuads(null, RDF.type, type, null) > 0);
    if (!hasPolicy) throw new Error("There must be at least one policy present.");

    if (new Store(state).countQuads(null, RDF.type, SOTW.SotW, null) !== 1) {
        throw new Error("There must be exactly one state of the world present.");
    }
}

export class ODRLEvaluator implements Evaluator {
    private readonly rdfValidator: RDFValidator;
    private readonly tripleTermValidator: TripleTermValidator;
    private readonly shaclValidator: SHACLValidator;
    private readonly engine: Engine

    constructor(engine = new ODRLEngine()) {
        this.rdfValidator = new RDFValidator();
        this.tripleTermValidator = new TripleTermValidator();
        this.shaclValidator = new SHACLValidator();

        // note the following is ugly, but for a first prototype it is fine
        this.engine = engine;
    }

    public async evaluate(policy: Quad[], request: Quad[], state: Quad[]): Promise<Quad[]> {
        // check if all parameters are RDF
        // if the parameters are not RDF, it is impossible to reason over them (or validate some structure)
        const policyValidRDF = await this.rdfValidator.simpleValidate(policy)
        const requestValidRDF = await this.rdfValidator.simpleValidate(request)
        const stateValidRDF = await this.rdfValidator.simpleValidate(state)
        if (!(policyValidRDF && requestValidRDF && stateValidRDF)) {
            const errorMessage = `Following input is not RDF: ${policyValidRDF ? "" : "policy, "} ${requestValidRDF ? "" : "request, "} ${stateValidRDF ? "" : "state"}.`
            throw Error(errorMessage);
        }

        // check whether parameters are true triples
        // if some parameters are quads, the reasoner might not execute
        const policyOnlyTriples = await this.tripleTermValidator.simpleValidate(policy)
        const requestOnlyTriples = await this.tripleTermValidator.simpleValidate(request)
        const stateOnlyTriples = await this.tripleTermValidator.simpleValidate(state)
        if (!(policyOnlyTriples && requestOnlyTriples && stateOnlyTriples)) {
            const errorMessage = `Following input contains quads: ${policyOnlyTriples ? "" : "policy, "} ${requestOnlyTriples ? "" : "request, "} ${stateOnlyTriples ? "" : "state"}.`
            throw Error(errorMessage);
        }
        // check whether the policy and request conform to the SHACL shape of ODRL
        // if not, it makes no sense to do ODRL evaluation

        // cardinality check: if there is no policy, nothing can be evaluated
        // Questions: can there be more than 1 policy or must it be exactly one?
        // There can be multiple policies -> see formal semantics group

        // policy decomposition must happen to reduce the rules in the policy to atomic rules
        // see ODRL § 2.7 Policy Rule Composition (https://www.w3.org/TR/odrl-model/#composition)
        // if there are compact policies -> they must be expanded (also reocmmended by ODRL § 2.7.1 Compact Policy)
        const normalizer = new Normalizer();
        const normalizedPolicy = await normalizer.normalise(policy)

        // handle dynamic policies
        const instantiatedPolicies = materializePolicy(normalizedPolicy, state);
        // evaluate
        // the evaluation will result into a conformance report
        const evaluation = await this.engine.evaluate([...instantiatedPolicies, ...request, ...state])

        // in case the rules had to be normalized, merge again
        const mergedEvaluation = mergeDerivedRuleReports(evaluation, normalizedPolicy);
        // TODO: think about when the report can be empty
        // does it always mean there is not enough information?
        // Is there any way to detect the missing information?

        return mergedEvaluation;
    }
}
