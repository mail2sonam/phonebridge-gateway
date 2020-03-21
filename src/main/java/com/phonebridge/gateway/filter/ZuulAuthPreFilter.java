package com.phonebridge.gateway.filter;

import java.util.Collection;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.Ordered;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

@Component
public class ZuulAuthPreFilter extends ZuulFilter {
	
	private static final String AUTHORITIES_KEY = "authorities";
			
	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() throws ZuulException {

		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request=ctx.getRequest();
		
		String userName="";
		Collection<? extends GrantedAuthority> grantedAuthorities = null;
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (principal instanceof UserDetails) {
			userName = ((UserDetails)principal).getUsername();
			grantedAuthorities = ((UserDetails) principal).getAuthorities();
		} else {
			userName = (String)principal;
			grantedAuthorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
		}
		if(!userName.contains("::"))
			return null;
		String grantedAuthoritiesStr = grantedAuthorities.stream().map(ga->ga.getAuthority()).collect(Collectors.joining(",")); 
		String[] usernameFromTokenArr = userName.split("::");
        ctx.addZuulRequestHeader("accountId", usernameFromTokenArr[0]);
        ctx.addZuulRequestHeader("userId", usernameFromTokenArr[1]);
        ctx.addZuulRequestHeader(AUTHORITIES_KEY, grantedAuthoritiesStr);
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
