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

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import java.util.Enumeration;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;

import org.owasp.stinger.actions.AbstractAction;
import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.rules.Rule;
import org.owasp.stinger.rules.CookieRule;
import org.owasp.stinger.rules.RuleSet;
import org.owasp.stinger.violation.Violation;
import org.owasp.stinger.violation.ViolationList;

public class Stinger {
	
	private final static int STOP = -1;
	
	private final static int CONTINUE = 0;
	
	private RuleSet set = null;
	
	private ServletContext context = null;
	
	public Stinger(RuleSet set, ServletContext context) {
		this.set = set;
		this.context = context;
	}
	
	private void handleViolationActions(MutableHttpRequest request, HttpServletResponse response, Violation violation) {
		List<AbstractAction> actions = violation.getActions();
		Iterator <AbstractAction>itr = actions.iterator();
		
		while(itr.hasNext()) {
			AbstractAction action = (AbstractAction)itr.next();
			
			action.doAction(violation, request, response);
		}
	}
	
	private void handleViolations(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) {
		Iterator <Violation> itr = vList.iterator();
		
		while(itr.hasNext()) {
			Violation violation = (Violation)itr.next();
			
			handleViolationActions(request, response, violation);
		}
	}
	
	private int checkMissingCookies(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) {
		int retval = CONTINUE;
		String uri = request.getRequestURI();
		Cookie[] cookies = request.getCookies();
		Map<String, Cookie> cookieMap = new HashMap<String, Cookie>();
		List<CookieRule> cRules = set.getCookieRules();
		
		if(cookies != null) {
			for(int i=0; i<cookies.length; i++) {
				cookieMap.put(cookies[i].getName(), cookies[i]);
			}
			Iterator<CookieRule> itr = cRules.iterator();
			
			while(itr.hasNext()) {
				CookieRule cRule = (CookieRule)itr.next();
				String name = cRule.getName();
				
				/** The cookie is considered missing if it DNE and we are NOT on the created URI **/
				/** Only enforce if we are in an enforcing uri **/
				
				if(!cookieMap.containsKey(name) && !cRule.isCreatedUri(uri) && cRule.isEnforced(uri)) {
					Violation violation = new Violation(cRule.getMissing(), name, null, cRule.getPattern(), uri);
					
					if(violation.getSeverity().equals(Severity.FATAL)) {
						handleViolationActions(request, response, violation);
						
						retval = STOP;
					} else if(violation.getSeverity().equals(Severity.CONTINUE)){
						vList.add(violation);
					} else {
						/** Severity == IGNORE **/
						context.log("[Stinger-Filter] - ignoring missing violation for the " + violation.getName() + " cookie");
					}					
				}
			}
		} else {
			/** There exists no rules for this URI **/
			context.log("[Stinger-Filter] - there exists no rules for the following URI: " + request.getRequestURI());
		}
		
		return retval;
	}
	
	private int checkMalformedCookies(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) {
		int retval = CONTINUE;
		String uri = request.getRequestURI();
		Cookie[] cookies = request.getCookies();
		
		if(cookies != null) {
			for(int i=0; i<cookies.length; i++) {
				Cookie cookie = cookies[i];
				CookieRule cRule = set.getCookieRule(cookie.getName());
				
				if(cRule != null && cRule.isEnforced(uri)) {
					if(!cRule.isValid(cookie.getValue())) {
						String name = cRule.getName();
						Violation violation = new Violation(cRule.getMissing(), name, cookie.getValue(), cRule.getPattern(), uri);
						
						if(violation.getSeverity().equals(Severity.FATAL)) {
							handleViolationActions(request, response, violation);
							
							retval = STOP;
						} else if(violation.getSeverity().equals(Severity.CONTINUE)){
							vList.add(violation);
						} else {
							/** Severity == IGNORE **/
							context.log("[Stinger-Filter] - ignoring malformed violation for the " + violation.getName() + " cookie");
						}
					}
				}	
			}
		}
		
		return retval;
	}
	
	private int checkMissingParameters(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) {
		int retval = CONTINUE;
		String uri = request.getRequestURI();
		List<Rule> pRules = set.getParameterRules(uri);
		
		if(pRules != null) {
			Iterator<Rule> itr = pRules.iterator();
			
			while(itr.hasNext()) {
				Rule pRule = (Rule)itr.next();
				String name = pRule.getName();
				
				if(!name.equals(RuleSet.STINGER_ALL) && (request.getParameter(name) == null || request.getParameter(name).equals(""))) {
					Violation violation = new Violation(pRule.getMissing(), name, null, pRule.getPattern(), uri);
					
					if(violation.getSeverity().equals(Severity.FATAL)) {
						handleViolationActions(request, response, violation);
						
						retval = STOP;
					} else if(violation.getSeverity().equals(Severity.CONTINUE)){
						vList.add(violation);
					} else {
						/** Severity == IGNORE **/
						context.log("[Stinger-Filter] - ignoring missing violation for the " + violation.getName() + " parameter at " + request.getRequestURI());
					}
				}
			}
		} else {
			/** There exists no rules for this uri **/
			context.log("[Stinger-Filter] there exists no rules for the following URI: " + request.getRequestURI());
		}
		
		return retval;
	}
	
	private int checkMalformedParameters(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) {
		int retval = CONTINUE;
		String uri = request.getRequestURI();
		Enumeration e = request.getParameterNames();
		
		while(e.hasMoreElements()) {
			String name = (String)e.nextElement();
			String value = request.getParameter(name);
			
			Rule pRule = set.getParameterRule(uri, name);
			
			if(pRule != null && !pRule.isValid(value)) {
				Violation violation = new Violation(pRule.getMalformed(), name, value, pRule.getPattern(), uri);
				
				if(violation.getSeverity().equals(Severity.FATAL)) {
					handleViolationActions(request, response, violation);
					
					retval = STOP;
				} else if(violation.getSeverity().equals(Severity.CONTINUE)){
					vList.add(violation);
				} else {
					/** Severity == IGNORE **/
					context.log("[Stinger-Filter] - ignoring malformed violation for the " + violation.getName() + " parameter at " + request.getRequestURI());
				}
			}
		}
		
		return retval;
	}
	
	private int doValidate(MutableHttpRequest request, HttpServletResponse response) {
		ViolationList vList = new ViolationList();
		int retval = checkMissingCookies(request, response, vList);
		
		if(retval == CONTINUE) {
			retval = checkMalformedCookies(request, response, vList);
			
			if(retval == CONTINUE) {
				retval = checkMissingParameters(request, response, vList);
				
				if(retval == CONTINUE) {
					retval = checkMalformedParameters(request, response, vList);
				}
			}
		}
		
		handleViolations(request, response, vList);
		return retval;
	}
	
	public int validate(MutableHttpRequest request, HttpServletResponse response) {
		int retval = -1;
		
		if(set.isExcluded(request.getRequestURI())) {
			retval = CONTINUE;
		} else {
			retval = doValidate(request, response);
		}
		
		return retval;
	}
}
