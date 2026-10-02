package com.courinha.oauth2.core;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.time.Instant;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Asserts the hexagon's dependency direction against the compiled classes.
 *
 * <p>The Maven module graph already makes the main violations impossible, and
 * {@code maven-enforcer} bans Spring from the inner modules. These rules add what the build
 * cannot express: intra-module package direction, and the rule that only the clock adapter
 * reads the wall clock — which is what stops expiry assertions from quietly going flaky.
 */
@AnalyzeClasses(packages = "com.courinha.oauth2.core", importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

    @ArchTest
    static final ArchRule domain_knows_nothing_outside_itself =
            noClasses().that().resideInAPackage("..core.domain..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "..core.application..",
                            "..core.adapter..",
                            "..core.config..");

    @ArchTest
    static final ArchRule application_knows_nothing_about_adapters =
            noClasses().that().resideInAPackage("..core.application..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "..core.adapter..",
                            "..core.config..");

    @ArchTest
    static final ArchRule only_the_clock_adapter_reads_the_wall_clock =
            noClasses().that().resideOutsideOfPackage("..adapter.out.time.system..")
                    .should().callMethod(Instant.class, "now");

    @ArchTest
    static final ArchRule only_the_clock_adapter_reads_the_system_clock =
            noClasses().that().resideOutsideOfPackage("..adapter.out.time.system..")
                    .should().callMethod(System.class, "currentTimeMillis");

    @ArchTest
    static final ArchRule the_web_adapter_is_the_only_one_using_spring_web =
            noClasses().that().resideOutsideOfPackage("..core.adapter.in.web..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "org.springframework.web..",
                            "org.springframework.http..",
                            "jakarta.servlet..");
}
