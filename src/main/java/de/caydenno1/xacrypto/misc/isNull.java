package de.caydenno1.xacrypto.misc;

import java.util.Objects;

public class isNull {
    public static boolean isNull(Object v) {
        return Objects.isNull(v) || v == null;
    }
    public boolean isNull(Object v, Object alt) {
        return Objects.isNull(v) || v == null || v == alt;
    }
    public static boolean isValidText(String s) {
        if (s.isBlank() || s.trim().isEmpty()) return false;
        switch (s) {
            case "":
            case null:
                return false;
            default:
                return true;
        }
    };
}
