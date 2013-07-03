package org.owasp.stinger.actions;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;

public class Forward extends AbstractAction {
	
	private ServletContext context = null;
	
	public void init(ServletContext context) {
		this.context = context;
	}
	
	public int doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) {
		String page = getParameter("page");
		
		try {
			request.getRequestDispatcher(page).forward(request, response);
		} catch (IOException ioe) {
			context.log("[Stinger-Filter] exception in doAction", ioe);
		} catch (ServletException se) {
			context.log("[Stinger-Filter] exception in doAction", se);
		}
		
		return PROCESS;
	}
}
