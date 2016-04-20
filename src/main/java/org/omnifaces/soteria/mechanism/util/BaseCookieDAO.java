/*
 * Copyright 2016 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.omnifaces.soteria.mechanism.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class BaseCookieDAO {

	public void save(HttpServletRequest request, HttpServletResponse response, String name, String value, Integer maxAge) {
		Cookie cookie = new Cookie(name, value);
		if (maxAge != null) {
			cookie.setMaxAge(maxAge);
		}
		cookie.setHttpOnly(true);
		cookie.setPath(Utils.isEmpty(request.getContextPath())? "/" : request.getContextPath());

		response.addCookie(cookie);
	}
	
	public Cookie get(HttpServletRequest request, String name) {
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (name.equals(cookie.getName()) && !isEmpty(cookie)) {
					return cookie;
				}
			}
		}

		return null;
	}

	public void remove(HttpServletRequest request, HttpServletResponse response, String name) {
		Cookie cookie = new Cookie(name, null);
		cookie.setMaxAge(0);
		cookie.setPath(Utils.isEmpty(request.getContextPath())? "/" : request.getContextPath());

		response.addCookie(cookie);
	}
	
	private boolean isEmpty(Cookie cookie) {
		return cookie.getValue() == null || cookie.getValue().trim().isEmpty();
	}
	
}
