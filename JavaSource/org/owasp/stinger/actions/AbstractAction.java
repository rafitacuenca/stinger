/**
 * Stinger is an HTTP Request Validation Engine
 * Copyright (C) 2006  Aspect Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Contact us at info@aspectsecurity.com or www.aspectsecurity.com
 *
 */

package org.owasp.stinger.actions;

import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;

public abstract class AbstractAction {
	
	public final static int DROP = -1;
	
	public final static int CONTINUE = 0;
	
	public final static int PROCESS = 1;
	
	private HashMap<String, String> parameters = new HashMap<String, String>();
	
	public String getParameter(String name) {
		return parameters.get(name);
	}
	
	public void setParameter(String name, String value) {
		parameters.remove(name);
		parameters.put(name, value);
	}
	
	public abstract void init(ServletContext context);
	
	public abstract int doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response);
}
