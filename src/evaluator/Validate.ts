import type { Quad } from "@rdfjs/types";
import { Store } from "n3";


export abstract class Validator<TIn = void, TOut = void> {
    /**
     * Returns a boolean result on whether the input was valid.
     * @param input input to be validated
     */
    public abstract simpleValidate(input: TIn): Promise<boolean>;

    /**
     * Calculates whether the input is valid
     * @param input
     */
    public abstract validate(input: TIn): Promise<TOut>;
}
export class RDFValidator extends Validator<Quad[], void> {
    constructor() {
        super();
        // Note: does this make sense? they are already quads
    }

    public async simpleValidate(quads: Quad[]) {
        await this.validate(quads);
        return true;
    }

    public async validate(quads: Quad[]): Promise<void> {
    }
}
export class TripleTermValidator extends Validator<Quad[], void> {
    constructor() {
        super();
    }

    public async simpleValidate(quads: Quad[]) {
        try {
            await this.validate(quads);
        }
        catch {
            return false;
        }
        return true;
    }

    public async validate(quads: Quad[]): Promise<void> {
        if (containsGraphs(quads)) throw new Error("quads contain graph elements, which must be thrown out before evaluating as the evaluator does not take those into account.");
    }
}
/**
 * Checks whether a store contains a graph other than the defaultGraph
 * @param store
 */
function containsGraphs(quads: Quad[]): boolean {
    const store = new Store(quads);
    const graphs = store.getGraphs(null, null, null);
    let status = false;
    switch (graphs.length) {
        case 0:
            status = false;
            break;
        case 1:
            if (graphs[0].id === '') {
                status = false;
            }
            else {
                status = true;
            }
            break;
        default:
            status = true;
            break;
    }

    return status;
}
export class SHACLValidator extends Validator<Quad[], void> {
    constructor() {
        super();
        // TODO: implement
        // NOTE: as input also needs an ODRL SHACL resource
        // also use SHACL engine in this one
    }

    public async simpleValidate(quads: Quad[]) {
        await this.validate(quads);
        return true;
    }

    public async validate(quads: Quad[]): Promise<void> {
    }
}
