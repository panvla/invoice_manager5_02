package com.vladimirpandurov.invoice_manager502.query;

public class UserQuery {

    public static final String COUNT_USER_EMAIL_QUERY = "SELECT COUNT(*) FROM Users WHERE email = :email";
    public static final String INSERT_USER_QUERY = "INSERT INTO Users (first_name, last_name, email , password) VALUES (:firstName, :lastName, :email, :password)";
    public static final String INSERT_ACCOUNT_VERIFICATION_URL_QUERY = "INSERT INTO AccountVerifications (user_id, url) VALUES (:userId, :url)";
    public static final String SELECT_USER_BY_EMAIL_QUERY = "SELECT * FROM Users WHERE email = :email";
    public static final String DELETE_VERIFICATION_CODE_BY_USER_ID = "DELETE FROM TwoFactorVerifications WHERE user_id = :id";
    public static final String INSERT_VERIFICATION_CODE_QUERY = "INSERT INTO TwoFactorVerifications (user_id, code, expiration_data) VALUES (:user_id, :code, :expirationDate)";
    public static final String SELECT_USER_BY_USER_CODE_QUERY = "SELECT * FROM Users WHERE id = (SELECT user_id FROM TwoFactorVerifications WHERE code = :code)";
    public static final String DELETE_CODE_BY_CODE = "DELETE FROM TwoFactorVerifications WHERE code = :code";
    public static final String SELECT_CODE_EXPIRATION_QUERY = "SELECT expiration_data < NOW() AS is_expired FROM TwoFactorVerifications WHERE code = :code";
}
