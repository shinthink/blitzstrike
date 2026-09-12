/** Shared AST node type for external untyped parser boundaries.
 *
 * php-parser, @babel/parser, @lezer/python, and java-parser all return
 * dynamically-shaped AST nodes without TypeScript typings. Rather than scatter
 * `any` across the codebase, we consolidate the boundary into this single,
 * documented alias. Downstream code narrows to the fields it needs (kind/type/
 * name/loc/children/...) instead of treating the whole node as opaque.
 *
 * The `any` here is intentional and bounded: it marks the exact point where a
 * third-party parser's untyped output enters our typed world.
 */
export type AstNode = Record<string, any>;
