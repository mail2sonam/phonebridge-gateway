package com.phonebridge.gateway.authserver.filter;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.phonebridge.gateway.authserver.config.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class ZuulAuthPreFilter extends ZuulFilter {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() throws ZuulException {

		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request=ctx.getRequest();
		
		final String requestTokenHeader = request.getHeader("Authorization");

		String jwtToken = requestTokenHeader.substring(7);
		try {
			String[] usernameFromTokenArr = jwtTokenUtil.getUsernameFromToken(jwtToken).split("::");
	        ctx.addZuulRequestHeader("accountId", usernameFromTokenArr[0]);
	        ctx.addZuulRequestHeader("userId", usernameFromTokenArr[1]);
		} catch (IllegalArgumentException e) {
			System.out.println("Unable to get JWT Token");
		} catch (ExpiredJwtException e) {
			System.out.println("JWT Token has expired");
		} 
	  return null;
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}

}
