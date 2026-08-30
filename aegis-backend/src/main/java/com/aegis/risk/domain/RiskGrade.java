package com.aegis.risk.domain;

public enum RiskGrade {
    A,
    B,
    C,
    D,
    E,
    F;

    public static RiskGrade fromScore(double score) {
        if (score < 15.00) return A;
        if (score < 35.00) return B;
        if (score < 60.00) return C;
        if (score < 80.00) return D;
        if (score < 90.00) return E;
        return F;
    }
}
