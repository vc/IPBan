using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Sync failed logins to ipthreat api
/// </summary>
/// <remarks>
/// Constructor
/// </remarks>
/// <param name="service">Service</param>
public sealed class IPBanIPThreatUploader(IPBanService service) : IUpdater, IIPAddressEventHandler
{
    private static readonly Uri ipThreatReportApiUri = new("https://api.ipthreat.net/api/bulkreport");

    private readonly IPBanService service = service;
    private readonly Random random = new();
    private readonly List<IPAddressLogEvent> events = [];

    private DateTime nextRun = IPBanService.UtcNow;

    /// <inheritdoc />
    public void Dispose()
    {

    }

    /// <inheritdoc />
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Anonymous payload shape is fixed and used only for IPThreat API upload.")]
    public async Task Update(CancellationToken cancelToken = default)
    {
        // ready to run?
        var now = IPBanService.UtcNow;
        if (now < nextRun)
        {
            return;
        }

        // copy events
        IPAddressLogEvent[] eventsCopy;
        lock (events)
        {
            eventsCopy = [.. events];
            events.Clear();
        }
        if (eventsCopy.Length == 0)
        {
            return;
        }

        // do we have an api key?
        var apiKey = (service.Config.IPThreatApiKey ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return;
        }

        // post json
        try
        {
            /*
            [{
                "ip": "1.2.3.4",
                "flags": "None",
                "system": "SMTP",
                "notes": "Failed password",
                "ts": "2022-09-02T15:24:07.842Z",
                "count": 1
            }]
            */
            var transform =
                eventsCopy.Select(e => new
                {
                    ip = e.IPAddress,
                    flags = "BruteForce",
                    system = e.Source,
                    notes = (service.AppName + " - " + (e.LogData ?? string.Empty)).Trim(' ', '-'),
                    ts = e.Timestamp.ToString("s", CultureInfo.InvariantCulture) + "Z",
                    count = e.Count
                });
            var jsonObj = new { items = transform };
            // have to use newtonsoft here
            var postJson = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj));

            // use proxy for ipthreat api only if configured, otherwise connect directly
            HttpClient client;
            var ipThreatProxyAddress = (service.Config.IPThreatProxyAddress ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(ipThreatProxyAddress))
            {
                client = new HttpClient();
            }
            else
            {
                var handler = new HttpClientHandler();
                handler.Proxy = new WebProxy(ipThreatProxyAddress);
                var ipThreatProxyUserName = (service.Config.IPThreatProxyUserName ?? string.Empty).Trim();
                var ipThreatProxyPassword = (service.Config.IPThreatProxyPassword ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(ipThreatProxyUserName) && !string.IsNullOrWhiteSpace(ipThreatProxyPassword))
                {
                    handler.Proxy.Credentials = new NetworkCredential(ipThreatProxyUserName, ipThreatProxyPassword);
                }
                client = new HttpClient(handler);
            }
            using (client)
            {
                HttpRequestMessage msg = new(HttpMethod.Post, ipThreatReportApiUri)
                {
                    Content = new ByteArrayContent(postJson)
                };
                msg.Content.Headers.Add("Content-Type", "application/json; charset=utf-8");
                msg.Headers.Add("X-API-KEY", apiKey);
                using var responseMsg = await client.SendAsync(msg, cancelToken);
                if (!responseMsg.IsSuccessStatusCode)
                {
                    throw new HttpRequestException("Request to " + ipThreatReportApiUri + " failed, status: " + responseMsg.StatusCode);
                }
            }
            Logger.Warn("Submitted {0} failed logins to ipthreat api", eventsCopy.Length);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to post json to ipthreat api, please double check your IPThreatApiKey setting");
        }

        // set next run time
        nextRun = now.AddMinutes(random.Next(30, 91));
    }

    /// <inheritdoc />
    public void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events)
    {
        // Run the filter outside the lock — the predicate calls into service.Config which we
        // don't want to hold the events lock across. Only the AddRange happens inside.
        var filtered = events.Where(e => e.Type == IPAddressEventType.Blocked &&
            e.Count > 0 &&
            !e.External &&
            !service.Config.IsWhitelisted(e.IPAddress, out _)).ToArray();
        if (filtered.Length == 0)
        {
            return;
        }
        // Qualify with `this.` so the lock targets the field — the parameter is also named
        // `events` and would otherwise shadow it, locking an unrelated caller-supplied object
        // while the field itself stayed unprotected.
        lock (this.events)
        {
            this.events.AddRange(filtered);
        }
    }
}
