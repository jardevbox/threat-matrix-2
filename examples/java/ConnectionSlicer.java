/*
*    ------ BEGIN LICENSE ATTRIBUTION ------
*    
*    Portions of this file have been appropriated or derived from the following project(s) and therefore require attribution to the original licenses and authors.
*    
*    Repository: https://github.com/spring-projects/spring-boot
*    Source File: spring-boot-project/spring-boot-devtools/src/main/java/org/springframework/boot/devtools/livereload/Connection.java
*    
*    Copyrights:
*      copyright 2012-2021 the original author or authors
*    
*    Licenses:
*      Apache License 2.0
*      SPDXId: Apache-2.0
*    
*    Auto-attribution by Threatrix, Inc.
*    
*    ------ END LICENSE ATTRIBUTION ------
*/
package io.threatrix.threatmatrix.slice;

import io.threatrix.common.component.ComponentRevisedLicenseDAO;
import io.threatrix.common.services.HumanNotificationService;
import io.threatrix.config.StaticConfig;
import io.threatrix.core.model.component.Component;
import io.threatrix.core.model.license.License;
import io.threatrix.ingest.apiimpl.deptrack.DependencyTrackResult;
import io.threatrix.ingest.dao.project.ComponentLicenseLookupService;

@Service
public class ConnectionSilce {


    private final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Autowired
    private ProjectDAO projectDAO;

    @Autowired
    private ComponentRevisedLicenseDAO componentRevisedLicenseDAO;


    @NotNull
    private Runnable setLicensesToComponentFunction(AtomicInteger componentsWithNoLicensesCnt, Component component) {
        return () -> {
            try {
                if (CollectionUtils.isEmpty(component.getLicenses())) {
                    List<License> lookedupLicenses = componentLicenseLookupService.lookupLicensesInKnowledgeBaseAndDepTrackAndRemoteSource(
                            component);
                    if (CollectionUtils.isNotEmpty(lookedupLicenses)) {
                        logger.info("Looked up licenses for {}", component.getName());
                        component.setLicenses(lookedupLicenses);
                    } else {
                        componentsWithNoLicensesCnt.getAndIncrement();
                    }
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        };
    }

    private void readWebSocketFrame() throws IOException {
		try {
			Frame frame = Frame.read(this.inputStream);
			if (frame.getType() == Frame.Type.PING) {
				writeWebSocketFrame(new Frame(Frame.Type.PONG));
			}
			else if (frame.getType() == Frame.Type.CLOSE) {
				throw new ConnectionClosedException();
			}
			else if (frame.getType() == Frame.Type.TEXT) {
				logger.debug(LogMessage.format("Received LiveReload text frame %s", frame));
			}
			else {
				throw new IOException("Unexpected Frame Type " + frame.getType());
			}
		}
		catch (SocketTimeoutException ex) {
			writeWebSocketFrame(new Frame(Frame.Type.PING));
			Frame frame = Frame.read(this.inputStream);
			if (frame.getType() != Frame.Type.PONG) {
				throw new IllegalStateException("No Pong");
			}
		}
	}

    /**
	 * Trigger livereload for the client using this connection.
	 * @throws IOException in case of I/O errors
	 */
	void triggerReload() throws IOException {
		if (this.webSocket) {
			logger.debug("Triggering LiveReload");
			writeWebSocketFrame(new Frame("{\"command\":\"reload\",\"path\":\"/\"}"));
		}
	}

    private void complementComponentLicenses(ProjectManifest projectManifest) {
        // fill all components with license data
        List<CompletableFuture<Void>> componentLicenseLookUpTasks = new LinkedList<>();
        AtomicInteger componentsWithNoLicensesCnt = new AtomicInteger();
        projectManifest.getAllComponents().forEach(
                component -> {
                    componentLicenseLookUpTasks.add(
                            CompletableFuture.runAsync(setLicensesToComponentFunction(componentsWithNoLicensesCnt, component), componentLicenseLookupExecutor)
                    );
                }
        );
        componentLicenseLookUpTasks.forEach(CompletableFuture::join);
        logger.info("Components with no licenses: {} of {}", componentsWithNoLicensesCnt.get(), projectManifest.getAllComponents().size());
    }


    /**
     * This method is used by both the UX ThreatScan, through QuickStartService and
     * directly by the ThreatAgent, which is not a SpringBoot app and cannot use
     * dependency injection.
     * <p>
     * The manifest, produced on the ThreatAgent(running in the customers environment)
     * serializes the ProjectManifest and ScanAsset features and sends them over the
     * internet to our server, which then deserializes and passes the ProjectManifest
     * to processProjectManifest for processing.
     *
     * @param projectDir
     * @param projectName
     * @param ignoredFiles
     * @return
     */
    public ProjectManifest buildProjectManifestTree(File projectDir, String projectName, List<IgnoredFiles> ignoredFiles) {
        logger.info("Looking for project manifests...");

        // File structure
        FileItem projectItem;
        if (scanMode.equals(ScanMode.PROJECT))
            projectItem = new FileStructureBuilder(verbose, ignoredFiles).build(projectDir);
        else {
            projectItem = new InMemoryDeviceStructureBuilder(verbose, lowMemoryMode).build(projectDir);
        }

        // project structure
        ProjectManifest projectManifest = new ProjectStructureBuilder().buildProjectStructure(projectItem, projectName);
        projectManifest.setName(projectName);
        return projectManifest;
    }

    public ProjectManifest buildProjectManifestTree(File projectDir, String projectName, ScanMode scanMode, boolean verbose, boolean lowMemoryMode, List<IgnoredFiles> ignoredFiles) {
        this.scanMode = scanMode;
        this.verbose = verbose;
        this.lowMemoryMode = lowMemoryMode;
        return buildProjectManifestTree(projectDir, projectName, ignoredFiles);
    }



}
