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

package org.owasp.stinger;

import java.io.File;
import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.rules.RuleSet;
import org.owasp.stinger.actions.AbstractAction;

public class StingerFilter implements Filter {
	
	private final static String POST = "POST";
	
	private final static String URL_FORM_ENCODING = "application/x-www-form-urlencoded";
	
	private Stinger stinger = null;
	
	private Object stingerLock = new Object();
	
	private String config = null;

	private Boolean reload = false;
	
	private String errorPage = null;
	
	private ServletContext context = null;
	
	
	public void init(FilterConfig filterConfig) {
		/** Get the servlet context for Stinger **/
		context = filterConfig.getServletContext();
		/** Pull config location from Filter init parameter **/
		String webINF = filterConfig.getServletContext().getRealPath("WEB-INF") + "/";
		config = webINF + filterConfig.getInitParameter("config");
		File configFile = new File(config);
		
		if(!configFile.exists() || !configFile.isFile()) context.log("[Stinger-Filter] (Error): unable to locate " + config + ". Attempting " + configFile.getAbsolutePath()); 
		
		/** Error page to display when exceptions are thrown **/
		errorPage = filterConfig.getInitParameter("error-page");
		/** Should we dynamically load the ruleset? **/
		reload = Boolean.valueOf(filterConfig.getInitParameter("reload"));
		/** Create a stinger instance **/
		stinger = new Stinger(new RuleSet(config, context), context);
	}
	
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		MutableHttpRequest mRequest = null;
		HttpServletResponse hResponse = null;
		
		if(request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			mRequest = new MutableHttpRequest((HttpServletRequest)request);
			hResponse = (HttpServletResponse)response;
			
			if(reload) {
				reloadStinger();
			}
			
			try {
				if(isValidRequest(mRequest)) {
					doStinger(mRequest, hResponse, chain);
				} else {
					context.log("[Stinger-Filter] caught a POST request with an incorrect content type header (" + mRequest.getContentType() + ") . Redirected to error page at " + errorPage);
					hResponse.sendRedirect(errorPage);
				}
			} catch(Exception e) {
				context.log("[Stinger-Filter] - " + e.getMessage(), e);
				
				try {
					hResponse.sendRedirect(errorPage);
				} catch (Exception ee) {
					context.log("[Stinger-Filter] error attempting to redirect to " + errorPage, ee);
				}
			}
		}
	}
	
	public void destroy() {
		
	}
	
	/**
	 * MULTIPART VALIDATION BYPASS FIX:
	 * 
	 * The Stinger validation relies on the J2EE servlet framework.
	 * By default, the framework only supports standard url-form-encoding
	 * for POST requests. If a multipart request comes through, however,
	 * request.getParameterNames() will return an empty enumeration. As a
	 * quick fix, we do not currently accept multipart-form-encoded post
	 * requests.
	 * @param request
	 * @return
	 */
	private boolean isValidRequest(MutableHttpRequest request)
	{
		boolean valid = true;
		String method = request.getMethod();
		String header = request.getContentType();
		
		if(POST.equalsIgnoreCase(method) && !URL_FORM_ENCODING.equalsIgnoreCase(header))
		{
			valid = false;
		}
		
		return valid;
	}
	
	private void doStinger(MutableHttpRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException
	{
		int retval = stinger.validate(request, response);
		
		switch(retval) {
			case AbstractAction.CONTINUE:
			case AbstractAction.PROCESS:
				chain.doFilter(request, response);
				break;
			case AbstractAction.DROP:
				break;
			default:
				break;
		}
	}
	
	private void reloadStinger()
	{
		synchronized(stingerLock) {
			stinger = new Stinger(new RuleSet(config, context), context);
		}
	}
}
