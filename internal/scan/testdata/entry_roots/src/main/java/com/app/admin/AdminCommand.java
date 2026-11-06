package com.app.admin;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

// AdminCommand registers a class with an admin console the application does
// not ship, so nothing in the application creates the class.
@Retention(RetentionPolicy.RUNTIME)
public @interface AdminCommand {}
