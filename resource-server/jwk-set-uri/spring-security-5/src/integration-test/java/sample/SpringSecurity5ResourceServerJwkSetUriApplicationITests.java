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
 * Integration tests for {@link SpringSecurity5ResourceServerJwkSetUriApplication}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SpringSecurity5ResourceServerJwkSetUriApplicationITests {

	String noScopesToken = "eyJraWQiOiJvbmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0In0.XeqIR1Dmw5R-N1LDYH7stYFpB3N9hrjTRw4ceQb5QiQepLZgbCdnQWFvKTNhHQJq9PfuPVWrqXACRlTWpDgUf1IZa1pQs4KrBvCKY2eepOLw77heCj9QSey1ChTb771FYmafYDpAXkH-q4DU0UR653Xzx4swMlmSwALNJuHlIObhHBI1AlwyTrq-kK1vwvvvjKsJP8v0dV8BqfpQ6VQ6Y9iYYaRpgTnBqc4YsTBFQysc-1dRqcwOl_Q0GHdzgDc_h8wuANWIt37_aDzBqsVZOvEgb8KNewZ_FH-N8xur5o72-2abHzGeDxd124KE3DGK4wMmtWBdYh28CAd7SDbxsw";
	String messageReadToken = "eyJraWQiOiJvbmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0Iiwic2NvcGUiOiJtZXNzYWdlOnJlYWQifQ.bmEe-Ir-FRo8dqmFEZBkLECYYL7k1_stlzCyvPYzAs6IkjlPmTTuprjAoRFz_AumzWByJdghkoQKgs9CRkptdmNfH6BkEYrG1rymLEDRI7B5LDihYi_VAws5TbtR4a7gVbUi6CYkqufJdXrnzXNaoexeXu5vWuc5z6DvsIGom-5TTIJupzxl-6dJbKzYbIKKdVaqaw0juRlhqvpmPboXpiWaNPMFBCNqNhxljJCRy_Zw9VPGia6zaJrGQ1V-yakdvmfjJsLFWvgTAqBSsgANepBsgB7iYlNMlxqMtyQ62zo0pVReNQB1h8_kgoHgoppB1-AAmouul-XaEkxtvO63iA";

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
