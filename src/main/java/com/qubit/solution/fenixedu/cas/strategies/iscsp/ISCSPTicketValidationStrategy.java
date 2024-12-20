/**
 * This file was created by Quorum Born IT <http://www.qub-it.com/> and its
 * copyright terms are bind to the legal agreement regulating the FenixEdu@ULisboa
 * software development project between Quorum Born IT and Serviços Partilhados da
 * Universidade de Lisboa:
 *  - Copyright © 2016 Quorum Born IT (until any Go-Live phase)
 *  - Copyright © 2016 Universidade de Lisboa (after any Go-Live phase)
 *
 * Contributors: paulo.abrantes@qub-it.com
 *
 *
 * This file is part of FenixEdu fenixedu-ulisboa-cas-strategies.
 *
 * FenixEdu fenixedu-ulisboa-cas-strategies is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FenixEdu fenixedu-ulisboa-cas-strategies is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FenixEdu fenixedu-ulisboa-cas-strategies.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.qubit.solution.fenixedu.cas.strategies.iscsp;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.fenixedu.academic.domain.Person;
import org.fenixedu.bennu.cas.client.CASClientConfiguration;
import org.fenixedu.bennu.cas.client.strategy.TicketValidationStrategy;
import org.fenixedu.bennu.core.domain.User;
import org.fenixedu.bennu.core.domain.exceptions.AuthorizationException;
import org.fenixedu.bennu.core.security.Authenticate;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.qubit.solution.fenixedu.integration.ldap.service.LdapIntegration;

import pt.ist.fenixframework.FenixFramework;

public class ISCSPTicketValidationStrategy implements TicketValidationStrategy {

    private static final Logger logger = LoggerFactory.getLogger(ISCSPTicketValidationStrategy.class);

    private final TicketValidator validator =
            new Cas30ServiceTicketValidator(CASClientConfiguration.getConfiguration().casServerUrl());

    @Override
    public void validateTicket(final String ticket, final String requestURL, final HttpServletRequest request,
            final HttpServletResponse response) throws TicketValidationException, AuthorizationException {

        Authenticate.logout(request, response);

        final String validationURL = requestURL.replace("http:", "https:");
        final Assertion validate = validator.validate(ticket, validationURL);
        final String principal = validate.getPrincipal().getName().trim().toLowerCase();
        final Map<String, Object> attributes = validate.getPrincipal().getAttributes();
        final String previousUsername = (String) attributes.get("previousUsername");
        final String degreeCode = (String) attributes.get("degreeCode");

        final String username =
                NumberUtils.isNumber(principal) && StringUtils.isNotBlank(degreeCode) ? degreeCode + "." + principal : principal;
        final User user = User.findByUsername(username);
        if (user != null) {
            Authenticate.login(request, response, user, "TODO: CHANGE ME");
            return;
        }

        final Person person = StringUtils.isNotBlank(previousUsername) ? Person.findByUsername(previousUsername) : null;
        if (person == null) {
            logger.error("Received valid username: " + username + " from CAS. User was not found look up by previous username: "
                    + previousUsername);
            throw AuthorizationException.authenticationFailed();
        }

        final boolean changedUserInLdap = LdapIntegration.changeULFenixUser(person, username);
        if (changedUserInLdap) {
            FenixFramework.getTransactionManager().withTransaction(() -> {
                User findByUsername = User.findByUsername(person.getUsername());
                if (findByUsername != null) {
                    findByUsername.align(username);
                }
                return null;
            });
        } else {
            logger.error("Unable to align: " + person.getUsername() + " to CN provided by CAS: " + username
                    + " Falling back to fenix username");
        }

        Authenticate.login(request, response, person.getUser(), "TODO: CHANGE ME");

    }
}
