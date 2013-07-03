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

package org.owasp.stinger.rules;

import java.util.regex.Pattern;

public class CookieRule extends Rule {
	
	private Pattern created = null;
	
	private Pattern enforced = null;
	
	public CookieRule() {
		
	}
	
	public String getCreated() {
		return created.pattern();
	}
	
	public void setCreated(String created) {
		this.created = Pattern.compile(created);
	}
	
	public boolean isCreatedUri(String uri) {
		return created.matcher(uri).matches();
	}
	
	public Pattern getEnforced() {
		return enforced;
	}
	
	public void setEnforced(String pattern) {
		enforced = Pattern.compile(pattern);
	}
	
	public boolean isEnforced(String uri) {
		return enforced.matcher(uri).matches();
	}
}
