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

package org.owasp.stinger.http;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedList;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class MutableHttpRequest extends HttpServletRequestWrapper {
	
	private final static String CONTENT_TYPE = "content-type";
	
	private HttpServletRequest request = null;
	
	private Map<String, LinkedList<String>> headers = new HashMap<String, LinkedList<String>>();
	
	private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
	
	private Map<String, String> parameters = new HashMap<String, String>();
	
	public MutableHttpRequest(HttpServletRequest request) {
		super(request);
		this.request = request;
		
		Enumeration e = request.getHeaderNames();
		
		while(e.hasMoreElements()) {
			String name = (String)e.nextElement();
			String value = request.getHeader(name);
			LinkedList<String> list = headers.get(name);
			
			if(list != null) {
				list.add(value);
			} else {
				list = new LinkedList<String>();
				list.add(value);
				headers.put(name, list);
			}
		}
		
		Cookie[] c = request.getCookies();
		
		if(c != null) {
			for(int i=0; i<c.length; i++) {
				cookies.put(c[i].getName(), c[i]);
			}
		}
		
		e = request.getParameterNames();
		
		while(e.hasMoreElements()) {
			String name = (String)e.nextElement();
			String value = request.getParameter(name);
			
			parameters.put(name, value);
		}
	}
	
	public HttpServletRequest getRequest() {
		return request;
	}
	
	public String getParameter(String name) {
		return parameters.get(name);
	}
	
	public void addParameter(String name, String value) {
		parameters.put(name, value);
	}
	
	public void removeParameter(String name) {
		parameters.remove(name);
	}
	
	public void clearParameters() {
		parameters = new HashMap<String, String>();
	}
	
	public Map getParameterMap() {
		return parameters;
	}
	
	public Enumeration getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}
	
	public String[] getParameterValues() {
		Collection<String> c = parameters.values();
		Enumeration e = Collections.enumeration(c);
		String[] values = new String[c.size()];
		
		for(int i=0; i<values.length; i++) {
			values[i] = (String)e.nextElement();
		}
		
		return values;
	}
	
	public String[] getParameterValues(String name) {
		String[] values = new String[1];
		
		values[0] = parameters.get(name);
		
		return values;
	}
	
	public Cookie[] getCookies() {
		Collection<Cookie> c = cookies.values();
		Enumeration e = Collections.enumeration(c);
		Cookie[] theCookies = new Cookie[c.size()];
		
		for(int i=0; i<theCookies.length; i++) {
			theCookies[i] = (Cookie)e.nextElement();
		}
		
		return theCookies;
	}
	
	public Cookie getCookie(String name) {
		return cookies.get(name);
	}
	
	public void setCookie(Cookie cookie) {
		cookies.put(cookie.getName(), cookie);
	}
	
	public void addCookie(Cookie cookie) {
		cookies.put(cookie.getName(), cookie);
	}
	
	public long getDateHeader(String name) {
		//FIXME: implement me
		return request.getDateHeader(name);
	}
	
	public String getHeader(String name) {
		String header = null;
		LinkedList<String> values = headers.get(name);
		
		if(values != null) {
			header = values.getFirst();
		}
		
		return header;
	}
	
	public void setHeader(String name, String value) {
		LinkedList<String> values = headers.get(name);
		
		if(values != null) {
			values.add(value);
		} else {
			values = new LinkedList<String>();
			values.add(value);
			headers.put(name, values);
		}
	}
	
	public Enumeration getHeaderNames() {
		return Collections.enumeration(headers.keySet());
	}
	
	public Enumeration getHeaders(String name) {
		return Collections.enumeration(headers.get(name));
	}
	
	public int getIntHeader(String name) throws NumberFormatException {
		int result = -1;
		LinkedList<String> values = headers.get(name);
		
		if(values != null) {
			String value = values.getFirst();
			result = Integer.parseInt(value);
		}
		
		return result;
	}
	
	public String getContentType() {
		String contentType = null;
		LinkedList<String> values = headers.get(CONTENT_TYPE);
		
		if(values != null && values.size() > 0) {
			contentType = values.get(0);
		}
		
		return contentType;
	}
}
