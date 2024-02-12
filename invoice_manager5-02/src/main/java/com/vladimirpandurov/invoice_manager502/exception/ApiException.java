package com.vladimirpandurov.invoice_manager502.exception;

public class ApiException extends RuntimeException{
    public ApiException(String message){
        super(message);
    }
}
