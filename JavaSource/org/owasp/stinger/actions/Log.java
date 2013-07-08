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

import static java.util.logging.Level.*;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;
import org.owasp.stinger.util.CryptoUtil;
import org.owasp.stinger.util.CryptoException;
import org.owasp.stinger.util.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Log extends AbstractAction {
	
	private static final Logger slog =
		LoggerFactory.getLogger(Log.class);
	
	public Log() {
		
	}
	
	public void init(ServletContext context) {
	}
	
	public int doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) {
		final Logger logger;
		String log = getParameter("log");
		if (log != null && !log.isEmpty()) {
			logger = LoggerFactory.getLogger(log);
		} else {
			logger = LoggerFactory.getLogger("stinger.log");
		}
		String level = getParameter("level");
		String message = getParameter("message");
		
		/** Offender's IP **/
		message = message.replace("%ip", request.getRemoteAddr());
		
		/** Offender's Port **/
		message = message.replace("%port", String.valueOf(request.getRemotePort()));
		
		/** Offending parameter name **/
		if(violation.getName() != null) {
			message = message.replace("%name", violation.getName());
		} else {
			message = message.replace("%name", "NULL");
		}
		
		/** Offending parameter value **/
		if(violation.getValue() != null) {
			message = message.replace("%value", violation.getValue());
		} else {
			message = message.replace("%value", "NULL");
		}
		
		/** Offending parameter value HTML Encoded **/
		if(violation.getValue() != null) {
			message = message.replace("%encoded_value", violation.getValue());
		} else {
			message = message.replace("%encoded_value", "NULL");
		}
		
		/** Offender's JSESSIONID (HASHED) **/
		if(request.getCookie("JSESSIONID") != null) {
			String s = request.getCookie("JSESSIONID").getValue();
			byte[] b = null;
			
			try {
				b = CryptoUtil.doWeakHash(s.getBytes());
			} catch (CryptoException e) {
				slog.error("[Stinger-Filter] caught crypto exception in doAction", e);
			}
			
			message = message.replace("%js", Encoder.BASE64Encode(b));
		} else {
			message = message.replace("%js", "NULL");
		}

		int parsedLevel = parse(level.toUpperCase()).intValue();
		if (parsedLevel == OFF.intValue()) {
			// do nothing
		} else if (parsedLevel >= SEVERE.intValue()) {
			logger.error(message);
		} else if (parsedLevel >= WARNING.intValue()) {
			logger.warn(message);
		} else if (parsedLevel >= INFO.intValue()) {
			logger.info(message);
		} else if (parsedLevel >= FINE.intValue()) {
			logger.debug(message);
		} else {
			logger.trace(message);
		}
		
		return CONTINUE;
	}
}
