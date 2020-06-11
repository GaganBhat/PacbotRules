
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.graph.auth.confidentialClient.ClientCredentialProvider;
import com.microsoft.graph.auth.enums.NationalCloud;
import com.microsoft.graph.models.extensions.DirectoryObject;
import com.microsoft.graph.models.extensions.DirectoryRole;
import com.microsoft.graph.models.extensions.IGraphServiceClient;
import com.microsoft.graph.requests.extensions.GraphServiceClient;
import com.microsoft.graph.requests.extensions.IDirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.requests.extensions.IDirectoryRoleCollectionPage;
import com.microsoft.rest.LogLevel;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.rule.Annotation;
import com.tmobile.pacman.commons.rule.BaseRule;
import com.tmobile.pacman.commons.rule.PacmanRule;
import com.tmobile.pacman.commons.rule.RuleResult;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;


import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

@PacmanRule(key = "azure-mfa-evaluation", desc = "Check whether MFA is enabled for Global/ Account Level Administrators.", severity = PacmanSdkConstants.SEV_HIGH, category = PacmanSdkConstants.SECURITY)
public class AzureMFACheck extends BaseRule {

	String admin_access = "AdministratorAccess";

	public static final Logger logger = LoggerFactory.getLogger(CheckAdminMFAEnabled.class);

	private static String auth_token = "";

	private static final String CLIENT_ID = "5883638a-eea1-4ef2-ab57-b4c8547f2696";
	private static final String CLIENT_SECRET = "";
	private static final String TENANT = "5c661468-61e8-450a-9561-52f21b84afa8";
	private static final String SCOPE = "https://graph.microsoft.com/.default";


	@Override
	public RuleResult execute(Map<String, String> ruleParam, Map<String, String> resourceAttributes) {
		logger.debug("======== Global Azure Admin MFA Account Check Started =========");

		Map<String, String> ruleParamIam = new HashMap<>();
		ruleParamIam.putAll(ruleParam);

		Map<String, Object> map = null;
		Azure azureClient = null;
		String roleIdentifyingString = ruleParam.get(PacmanSdkConstants.Role_IDENTIFYING_STRING);

		String severity = ruleParam.get(PacmanRuleConstants.SEVERITY);
		String category = ruleParam.get(PacmanRuleConstants.CATEGORY);

		MDC.put(PacmanSdkConstants.EXECUTION_ID, ruleParam.get(PacmanSdkConstants.EXECUTION_ID));
		MDC.put(PacmanSdkConstants.RULE_ID, ruleParam.get(PacmanSdkConstants.RULE_ID));

		Annotation annotation = null;

		if (!PacmanUtils.doesAllHaveValue(severity, category)) {
			logger.info(PacmanRuleConstants.MISSING_CONFIGURATION);
			throw new InvalidInputException(PacmanRuleConstants.MISSING_CONFIGURATION);
		}

		ClientCredentialProvider authorizationCodeProvider =
				new ClientCredentialProvider(
						CLIENT_ID,
						Arrays.asList("https://graph.microsoft.com/.default"),
						CLIENT_SECRET,
						TENANT,
						NationalCloud.Global
				);


		IGraphServiceClient graphClient = GraphServiceClient.builder().authenticationProvider(authorizationCodeProvider).buildClient();

		try {
			IDirectoryRoleCollectionPage directoryRoleCollectionPage = graphClient.directoryRoles().buildRequest().get();
			for (DirectoryRole role : directoryRoleCollectionPage.getCurrentPage()) {
				if (role.displayName.toLowerCase().contains("administrator")) {
					IDirectoryObjectCollectionWithReferencesPage members = graphClient.directoryRoles(role.id).members()
							.buildRequest()
							.get();

					for (DirectoryObject object : members.getCurrentPage()) {
						if(!isMFAEnabled(object.getRawObject().get("id").getAsString())) {
							logger.error("");
							return new RuleResult(PacmanSdkConstants.STATUS_FAILURE, PacmanRuleConstants.FAILED_MESSAGE);
						}
					}
				}
			}
		} catch (Exception e) {
			logger.error("PERMISSIONS ERROR - FAILED TO GET INFO 403, CHECK GRAPH API PERMISSIONS ", e);
			return new RuleResult(PacmanSdkConstants.STATUS_FAILURE, PacmanRuleConstants.FAILED_MESSAGE);
		}

		return new RuleResult(PacmanSdkConstants.STATUS_SUCCESS, PacmanRuleConstants.SUCCESS_MESSAGE);
	}

	@Override
	public String getHelpText() {
		return "Check whether MFA is enabled for Global/ Account Level Administrators";
	}

	public static void getAuthToken(){
		try {
			CloseableHttpClient client = HttpClients.createDefault();
			HttpPost httpPost = new HttpPost(String.format("https://login.microsoftonline.com/%s/oauth2/v2.0/token", TENANT));

			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("grant_type", "client_credentials"));
			params.add(new BasicNameValuePair("client_id", CLIENT_ID));
			params.add(new BasicNameValuePair("client_secret", CLIENT_SECRET));
			params.add(new BasicNameValuePair("scope", SCOPE));
			httpPost.setEntity(new UrlEncodedFormEntity(params));

			CloseableHttpResponse response = client.execute(httpPost);
			assert response.getStatusLine().getStatusCode() == 200;

			InputStream inputStream = response.getEntity().getContent();
			JSONObject jsonObject = (JSONObject) new JSONParser().parse(
					new InputStreamReader(inputStream, "UTF-8"));

			auth_token = (String) jsonObject.get("access_token");

			client.close();
		} catch (Exception e ){e.printStackTrace();}
	}

	public static boolean isMFAEnabled(String displayName) {
		try {
			CloseableHttpClient client = HttpClients.createDefault();
			HttpGet httpGet = new HttpGet(String.format(
					"https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?$filter=startswith(id,'%s')",
					displayName));
			httpGet.setHeader("Authorization", "Bearer " + auth_token);

			CloseableHttpResponse response = client.execute(httpGet);

			InputStream inputStream = response.getEntity().getContent(); //Read from a file, or a HttpRequest, or whatever.
			JSONObject mainJSONResult = (JSONObject) new JSONParser().parse(
					new InputStreamReader(inputStream, "UTF-8"));

			String userValUnformatted = mainJSONResult.get("value").toString();
			JSONObject userValues = (JSONObject) new JSONParser().parse(
					userValUnformatted.substring(1, userValUnformatted.length() - 1));

			if(userValues.get("isMfaRegistered").equals("true"))
				return true;

		} catch (Exception e ){
			System.out.println("Neither tenant is B2C or tenant doesn't have premium license possibly");
			e.printStackTrace();
		}

		return false;
	}


}
