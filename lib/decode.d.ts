export interface JwtParts {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
    raw: {
        header: string;
        payload: string;
        signature: string;
    };
}
export interface JwtInspection extends JwtParts {
    issues: string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    isExpired?: boolean;
    expiresInSeconds?: number;
    summaryLines: string[];
}
export declare function decodeJwt(token: string): JwtParts;
export declare function inspectJwt(token: string, nowSeconds?: number): JwtInspection;
//# sourceMappingURL=decode.d.ts.map