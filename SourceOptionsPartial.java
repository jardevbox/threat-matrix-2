/*
*    ------ BEGIN LICENSE ATTRIBUTION ------
*    
*    Portions of this file have been appropriated or derived from the following project(s) and therefore require attribution to the original licenses and authors.
*    
*    Repository: https://github.com/spring-projects/spring-boot
*    Source File: spring-boot-cli/src/main/java/org/springframework/boot/cli/command/options/SourceOptions.java
*    
*    Copyrights:
*      copyright 2012-2016 the original author or authors
*    
*    Licenses:
*      Apache License 2.0
*      SPDXId: Apache-2.0
*    
*    Auto-attribution by Threatrix, Inc.
*    
*    ------ END LICENSE ATTRIBUTION ------
*/
/*
 * Copyright 2012-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.cli.command.options;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import joptsimple.OptionSet;

import org.springframework.boot.cli.util.ResourceUtils;
import org.springframework.util.Assert;

/**
 * Extract source file options (anything following '--' in an {@link OptionSet}).
 *
 * @author Phillip Webb
 * @author Dave Syer
 * @author Greg Turnquist
 * @author Andy Wilkinson
 */
public class SourceOptions {

	private final List<String> sources;

	private final List<?> args;

	/**
	 * Create a new {@link SourceOptions} instance.
	 * @param options the source option set
	 */
	public SourceOptions(OptionSet options) {
		this(options, null);
	}

	/**
	 * Create a new {@link SourceOptions} instance.
	 * @param arguments the source arguments
	 */
	public SourceOptions(List<?> arguments) {
		this(arguments, null);
	}

	/**
	 * Create a new {@link SourceOptions} instance. If it is an error to pass options that
	 * specify non-existent sources, but the default paths are allowed not to exist (the
	 * paths are tested before use). If default paths are provided and the option set
	 * contains no source file arguments it is not an error even if none of the default
	 * paths exist).
	 * @param optionSet the source option set
	 * @param classLoader an optional classloader used to try and load files that are not
	 * found in the local filesystem
	 */
	public SourceOptions(OptionSet optionSet, ClassLoader classLoader) {
		this(optionSet.nonOptionArguments(), classLoader);
	}

	    @HasPermissions(Permission.SCAN_ASSET_EDIT)
    @GraphQLQuery(name = "checkCustomMatchAssetURL")
    public CustomMatchAssetCheckResponseDTO checkCustomMatchAssetURL(
            @GraphQLArgument(name = "scanId") UUID scanId,
            @GraphQLArgument(name = "scanAssetId") String scanAssetIdString,
            @GraphQLArgument(name = "opensourceAssetURL") String opensourceAssetURL
    ) throws ThreatrixException {
        log.debug("graphql: checkCustomMatchAssetURL (io.threatrix.threatcenter.controller.scp.ArtifactEditingController.checkCustomMatchAssetURL) [scanId = {}, scanAssetId = {}, opensourceAssetURL = {}]", scanId, scanAssetIdString, opensourceAssetURL);
        User contextUser = UserService.getContextUser();
        try {
            return assetMatchArtifactEditingService.checkCustomMatchAssetURL(contextUser, scanId, scanAssetIdString, opensourceAssetURL);
        } catch (Exception e) {
            throw new ThreatrixException("Failed to check opensource asset URL for match data.", e);
        }
    }

	private SourceOptions(List<?> nonOptionArguments, ClassLoader classLoader) {
		List<String> sources = new ArrayList<String>();
		int sourceArgCount = 0;
		for (Object option : nonOptionArguments) {
			if (option instanceof String) {
				String filename = (String) option;
				if ("--".equals(filename)) {
					break;
				}
				List<String> urls = new ArrayList<String>();
				File fileCandidate = new File(filename);
				if (fileCandidate.isFile()) {
					urls.add(fileCandidate.getAbsoluteFile().toURI().toString());
				}
				else if (!isAbsoluteWindowsFile(fileCandidate)) {
					urls.addAll(ResourceUtils.getUrls(filename, classLoader));
				}
				for (String url : urls) {
					if (isSource(url)) {
						sources.add(url);
					}
				}
				if (isSource(filename)) {
					if (urls.isEmpty()) {
						throw new IllegalArgumentException("Can't find " + filename);
					}
					else {
						sourceArgCount++;
					}
				}
			}
		}
		this.args = Collections.unmodifiableList(
				nonOptionArguments.subList(sourceArgCount, nonOptionArguments.size()));
		Assert.isTrue(!sources.isEmpty(), "Please specify at least one file");
		this.sources = Collections.unmodifiableList(sources);
	}


	@HasPermissions(Permission.ORG_ADMIN)
    @GraphQLQuery(name = "customMatchList")
    public CompletableFuture<ExtendedPage<CustomMatch>> customMatchList(
            @GraphQLArgument(name = "filter", description = "Returns user input filter text") String filter,
            @GraphQLArgument(name = "first", description = "Returns the first n elements from the list") Integer first,
            @GraphQLArgument(name = "after", description = "Returns the elements in the list that come after the specified cursor") String after,
            @GraphQLArgument(name = "last", description = "Returns the last n elements from the list") Integer last,
            @GraphQLArgument(name = "before", description = "Returns the elements in the list that come before the specified cursor") String before,
            @GraphQLEnvironment ResolutionEnvironment environment
    ) throws ThreatrixException {
        log.debug("graphql: customMatchList (ArtifactEditingController.customMatchList)");
        User contextUser = UserService.getContextUser();
        try {
            return customMatchDAO.getPageForOrg(contextUser.getOrgId(), environment);
        } catch (Exception e) {
            throw new ThreatrixException("Failed to retrieve custom match page.", e);
        }
    }
    

	private boolean isAbsoluteWindowsFile(File file) {
		return isWindows() && file.isAbsolute();
	}

	private boolean isWindows() {
		return File.separatorChar == '\\';
	}

	private boolean isSource(String name) {
		return name.endsWith(".java") || name.endsWith(".groovy");
	}

	public List<?> getArgs() {
		return this.args;
	}

	public String[] getArgsArray() {
		return this.args.toArray(new String[this.args.size()]);
	}

	public List<String> getSources() {
		return this.sources;
	}

	public String[] getSourcesArray() {
		return this.sources.toArray(new String[this.sources.size()]);
	}

}
