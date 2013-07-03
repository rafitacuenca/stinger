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

import java.io.File;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.owasp.stinger.Category;
import org.owasp.stinger.Severity;
import org.owasp.stinger.actions.AbstractAction;


public class RuleSet {
	
	/** Denotes a default ruleset **/
	public final static String STINGER_DEFAULT = "STINGER_DEFAULT";
	
	/** Denotes all parameters for a particular uri **/
	public final static String STINGER_ALL = "STINGER_ALL";
	
	/** The servlet context which gives us a basic logging facility **/
	private ServletContext context = null;
	
	/** The exclude-set which no protection will be applied **/
	private List<Pattern> excludeSet = new LinkedList<Pattern>();
	
	/** Double-Map of all parameter rules for a particular URI **/
	private Map<Pattern, Map<String, Rule>> pRules = new HashMap<Pattern, Map<String, Rule>>();
	
	/** Map of all cookie rules **/
	private Map<String, CookieRule> cRules = new HashMap<String, CookieRule>();
	
	/** Map of all regular expressions **/
	private Map<String, String> regexs = new HashMap<String, String>();
	
	private Document parseXmlFile(String fileName) {
		Document doc = null;
		DocumentBuilderFactory bf = null;
		
		try {
			bf = DocumentBuilderFactory.newInstance();
			doc = bf.newDocumentBuilder().parse(new File(fileName));
		} catch (Exception e) {
			context.log("[Stinger-Filter] (Error): exception while paring xml file", e);
		}
		
		return doc;
	}
	
	private RuleSet() {
		
	}
	
	public RuleSet(String config, ServletContext context) {
		this.context = context;
		parseRules(config);
	}
	
	private String getField(Element e, String key) {
		String field = null;
		
		if(e != null) {
			NodeList nl = e.getElementsByTagName(key);
			
			if(nl != null && nl.getLength() > 0) {
				Node n = nl.item(0);
				
				if(n.getNodeType() == Node.ELEMENT_NODE) {
					e = (Element)n;
					
					field = getValue(e);
				}
			} else {
				context.log("[Stinger-Filter] (Error): getField() element " + getValue(e) + " has no child element " + key);
			}
		}
		
		return field;
	}
	
	private String getValue(Element e) {
		return e.getFirstChild().getNodeValue().trim();
	}
	
	private void parseParameters(Element e, AbstractAction action) {
		NodeList parameters = null;
		Node child = null;
		Element pe = null;
		String name = null;
		String value = null;
		
		parameters = e.getElementsByTagName("parameter");
		
		for(int i=0; i<parameters.getLength(); i++) {
			child = (Node)parameters.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				pe = (Element)child;
				
				name = getField(pe, "name");
				value = getField(pe, "value");
				
				action.setParameter(name, value);
			}
		}
	}
	
	private void parseActions(Element e, Rule rule, Category c) {
		NodeList actions = null;
		String className = null;
		Class actionClass = null;
		Object possibleAction = null;
		AbstractAction action = null;
		Node child = null;
		Element ae = null;
		
		actions = e.getElementsByTagName("action");
		
		for(int i=0; i<actions.getLength(); i++) {
			child = (Node)actions.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				ae = (Element)child;
				
				try {
					className = ae.getAttribute("class");
					actionClass = Class.forName(className);
					possibleAction = actionClass.newInstance();
					
					if(possibleAction instanceof AbstractAction) {
						action = (AbstractAction)possibleAction;
						
						parseParameters(ae, action);
						
						action.init(context);
						
						c.addAction(action);
					}
				} catch (ClassNotFoundException cnfe) {
					context.log("[Stinger-Filter] (Error): exception while instantiating action", cnfe);
				} catch (InstantiationException ie) {
					context.log("[Stinger-Filter] (Error): exception while instantiating action", ie);
				} catch (IllegalAccessException iae) {
					context.log("[Stinger-Filter] (Error): exception while instantiating action", iae);
				}
			}
		}
	}
	
	private void parseMissing(Element e, Rule rule) {
		NodeList nl = e.getElementsByTagName("missing");
		
		if(nl == null || nl.getLength() <= 0) {
			context.log("[Stinger-Filter] (Error): the \"missing\" element not found for rule " + rule.getName());
			return;
		}
		
		Element miss = (Element)nl.item(0);
		String severity = null;
		Category missing = null;
		
		severity = getField(miss, "severity");
		missing = new Category(Category.MISSING, Severity.valueOf(severity));
		
		parseActions(miss, rule, missing);
		
		rule.setMissing(missing);
	}
	
	private void parseMalformed(Element e, Rule rule) {
		NodeList nl = e.getElementsByTagName("malformed");
		
		if(nl == null || nl.getLength() <= 0) {
			context.log("[Stinger-Filter] (Error): the \"malformed\" element not found for rule " + rule.getName());
			return;
		}
		
		Element mal = (Element)nl.item(0);
		String severity = getField(mal, "severity");
		Category malformed = new Category(Category.MALFORMED, Severity.valueOf(severity));
		
		parseActions(mal, rule, malformed);
		
		rule.setMalformed(malformed);
	}
	
	private Pattern getPath(Element e) {
		String path = getField(e, "path");
		Pattern p = null;
		
		try {
			p = Pattern.compile(path);
		} catch (PatternSyntaxException pse) {
			context.log("[Stinger-Filter] (Error): the following path pattern does not compile - " + path);
		}
		
		return p;
	}
	
	private void parseExcludeSet(Element root) {
		if(root.getElementsByTagName("exclude-set").getLength() > 0) {
			Element excludeSetE = (Element)root.getElementsByTagName("exclude-set").item(0);
			NodeList excludeChildren = excludeSetE.getElementsByTagName("exclude");
			
			for(int i=0; i<excludeChildren.getLength(); i++) {
				Node n = (Node)excludeChildren.item(i);
				
				if(n.getNodeType() == Node.ELEMENT_NODE) {
					Element exclude = (Element)n;
					String uri = getValue(exclude);
					Pattern p = Pattern.compile(uri);
					
					excludeSet.add(p);
				}
			}
		}
	}
	
	private void parseRegexSet(Element root) {
		/** Parse RegExs **/
		NodeList nl = root.getElementsByTagName("regexset");
		
		if(nl == null || nl.getLength() <= 0) {
			context.log("[Stinger-Filter] (Error): there are no regular expressions defined in the regexset element");
			return;
		}
		
		Element regexset = (Element)nl.item(0);
		NodeList children = regexset.getElementsByTagName("regex");
		
		for(int i=0; i<children.getLength(); i++) {
			Node child = (Node)children.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				Element e = (Element)child;
				
				String name = getField(e, "name");
				String pattern = getField(e, "pattern");
				
				regexs.put(name, pattern);
			}
		}
	}
	
	private void parseCookies(Element root) {
		NodeList cookies = root.getElementsByTagName("cookie");
		
		for(int i=0; i<cookies.getLength(); i++) {
			Node child = (Node)cookies.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				Element cookie = (Element)child;
				CookieRule cRule = new CookieRule();
				
				cRule.setName(getField(cookie, "name"));
				cRule.setPattern(regexs.get(getField(cookie, "regex")));
				cRule.setCreated(getField(cookie, "created"));
				cRule.setEnforced(getField(cookie, "enforce"));
				
				/** Parse Missing **/
				parseMissing(cookie, cRule);
				
				/** Parse Malformed **/
				parseMalformed(cookie, cRule);
				
				/** Add Newly Parsed Cookie Rule **/
				cRules.put(cRule.getName(), cRule);
			}
		}
	}
	
	private void parseRuleSets(Element root) {
		NodeList ruleSets = root.getElementsByTagName("ruleset");
		
		for(int i=0; i<ruleSets.getLength(); i++) {
			Node child = (Node)ruleSets.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				Element ruleSet = (Element)child;
				Pattern path = getPath(ruleSet);
				HashMap<String, Rule> rules = new HashMap<String, Rule>();
				
				NodeList children = ruleSet.getElementsByTagName("rule");
				
				for(int j=0; j<children.getLength(); j++) {
					child = (Node)children.item(j);
					
					if(child.getNodeType() == Node.ELEMENT_NODE) {
						Element e = (Element)child;
						Rule pRule = new Rule();
						
						pRule.setName(getField(e, "name"));
						
						String pattern = regexs.get(getField(e, "regex"));
						
						/** If there exists no associated regex,
						 *  then use input as regex
						 */
						if(pattern == null) {
							pattern = getField(e, "regex");
						}
						
						pRule.setPattern(pattern);
						
						/** Parse Exclude **/
						parseExclude(e, pRule);
						
						/** Parse Missing **/
						parseMissing(e, pRule);
						
						/** Parse Malformed **/
						parseMalformed(e, pRule);
						
						/** Add Newly Parsed Parameter Rule **/
						rules.put(pRule.getName(), pRule);
					}
				}
				
				pRules.put(path, rules);
			}
		}
	}
	
	private void parseRules(String config) {
		Document d = parseXmlFile(config);
		Element root = d.getDocumentElement();
		
		parseExcludeSet(root);
		parseRegexSet(root);
		parseCookies(root);
		parseRuleSets(root);
	}
	
	private void parseExclude(Element e, Rule rule) {
		NodeList children = e.getElementsByTagName("exclude");
		
		if(children != null && children.getLength() > 0) {
			for(int i=0; i<children.getLength(); i++) {
				Node n = (Node)children.item(i);
				
				if(n.getNodeType() == Node.ELEMENT_NODE) {
					Element excludeElement = (Element)n;
					String value = getValue(excludeElement);
					
					rule.addExclude(value);
				}
			}
		}
	}
	
	public Rule getParameterRule(String uri, String parameterName) {
		Rule rule = null;
		Map <String, Rule> uriRules = null;
		
		uriRules = getRules(uri);
		
		if(uriRules == null) {
			context.log("[Stinger-Filter](Warning): using default parameter rule for parameter " + parameterName);
			uriRules = getRules(STINGER_DEFAULT);
			rule = uriRules.get(STINGER_ALL);
		} else {
			rule = uriRules.get(parameterName);
			
			/** If no rule exists for this particular URI, then get defaults **/
			if(rule == null) {
				rule = uriRules.get(STINGER_ALL);
				
				/** No STINGER_ALL rule was defined for this URI, get Global Default **/
				if(rule == null) {
					uriRules = getRules(STINGER_DEFAULT);
					rule = uriRules.get(STINGER_ALL);
				}
			}
		}
		
		return rule;
	}
	
	public Map<String, Rule> getRules(String uri) {
		Map<String, Rule> rules = null;
		Enumeration e = Collections.enumeration(pRules.keySet());
		
		while(e.hasMoreElements()) {
			Pattern p = (Pattern)e.nextElement();
			
			if(p.matcher(uri).matches()) {
				rules = pRules.get(p);
			}
		}
		
		return rules;
	}
	
	public List<Rule> getParameterRules(String uri) {
		List<Rule> result = null;
		Iterator itr = null;
		Map<String, Rule> uriRules = null;
		String name = null;
		Rule rule = null;
		
		uriRules = getRules(uri);
		result = new LinkedList<Rule>();
		
		if(uriRules != null) {
			itr = uriRules.keySet().iterator();
			
			while(itr.hasNext()) {
				name = (String)itr.next();
				rule = (Rule)uriRules.get(name);
				
				result.add(rule);
			}
		} else {
			/** Get Default Rules **/
			context.log("[Stinger-Filter](WARNING): using default rules for uri " + uri);
			uriRules = getRules(STINGER_DEFAULT);
			
			result.add(uriRules.get(STINGER_ALL));
		}
		
		return result;
	}
	
	public CookieRule getCookieRule(String cookieName) {
		return cRules.get(cookieName);
	}
	
	public LinkedList<CookieRule> getCookieRules() {
		LinkedList<CookieRule> result = null;
		Iterator itr = null;
		String name = null;
		
		result = new LinkedList<CookieRule>();
		itr = cRules.keySet().iterator();
		
		while(itr.hasNext()) {
			name = (String)itr.next();
			
			result.add(cRules.get(name));
		}
		
		return result;
	}
	
	public Map<String, String> getRegexs() {
		return regexs;
	}
	
	public void addParameterRule(String uri, Rule newRule) {
		Enumeration e = Collections.enumeration(pRules.keySet());
		boolean isSet = false;
		Map<String, Rule> ruleSet = null;
		
		while(e.hasMoreElements()) {
			Pattern p = (Pattern)e.nextElement();
			
			if(p.matcher(uri).matches()) {
				ruleSet = pRules.get(p);
				ruleSet.put(newRule.getName(), newRule);
				isSet = true;
			}
		}
		
		if(isSet == false) {
			ruleSet = new HashMap<String, Rule>();
			ruleSet.put(newRule.getName(), newRule);
			pRules.put(Pattern.compile(uri), ruleSet);
		}
	}
	
	public Map<Pattern, Map<String, Rule>> getParameterRules() {
		return pRules;
	}
	
	public boolean isExcluded(String uri) {
		Iterator itr = excludeSet.iterator();
		boolean isExcluded = false;
		
		while(itr.hasNext()) {
			Pattern p = (Pattern)itr.next();
			
			if(p.matcher(uri).matches()) {
				isExcluded = true;
				break;
			}
		}
		
		return isExcluded;
	}
}
