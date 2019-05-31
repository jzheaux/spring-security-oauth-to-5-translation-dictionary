/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@link SpringSecurityOAuthResourceServerJwkSetUriApplication}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SpringSecurityOAuthResourceServerJwkSetUriApplicationITests {

	String noScopesToken = "eyJraWQiOiJvbmUiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX25hbWUiOiJzdWJqZWN0In0.V2KfX715uJlF8_WDDy8TJVlLO-XgH9xf7iW4327T76uiOZHUZkv56wxPa2QJoLO6-mxwRpSpUj5sE33GkCAck5WtJZxDWy-Nn24HvsovrK0vhZ3pPl-HAuzKsMjQbg00m9szu_yZGiAiHAC8taqdxjJ-A4w88lhtbJLB4ODbpdmnSl_VF7TSE3C1ZCdO6VN_hPrrVh-Ery0rKSYY7BTUZ9cy09c1fSYIqDe6R0MUBYSBEiflWVRpqDKyROPF9bV4u30sA-m7rSUTwj7URqUUVX-p17yHxnBHhmtrttzxNbz8_aCgY62Se12TMuhewV30X6HuhHQPo4KSQwEAaU6CEw";
	String messageReadToken = "eyJraWQiOiJvbmUiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX25hbWUiOiJzdWJqZWN0Iiwic2NvcGUiOiJtZXNzYWdlOnJlYWQifQ.QlMCtt7aUqJSaiN_u9fiK3pGUhMS4VNC4-wuGwdyDQ0pZcvHR5fqkYDS2HNN7cRU0ZBt86WvmREF85S7q0Z6olACjrFHcjvIWBc61OrjbxIqOAnFzPL9dik1UMH5SjnPDUFSfb5QHvut5JjEDOZWFWjW6LQGpjutFrbqe7cNCujETIArKCt4d20GEjugDeqIojDxHHWWKfd-TPiNyy2YXuR8SSQizJ4JTNHaQpj1mMfB6SKa87vr475NkFJ6qHWzNKnEytkiOvMYSwhtRpbE65FcBx5aTVte6ObfSKkYEyWhGxm4U_8Qds_Lh5ZJfTh4xnY63R59wDb_KqZf3gZkWg";

	@Autowired
	MockMvc mvc;

	@Test
	public void performWhenValidBearerTokenThenAllows()
		throws Exception {

		this.mvc.perform(get("/").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject!")));
	}

	// -- tests with scopes

	@Test
	public void performWhenValidBearerTokenThenScopedRequestsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.messageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message")));
	}

	@Test
	public void performWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\"")));
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private String token;

		public BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader("Authorization", "Bearer " + this.token);
			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}
}
