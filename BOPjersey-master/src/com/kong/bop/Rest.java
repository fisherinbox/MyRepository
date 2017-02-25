package com.kong.bop;

import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Path("/rest")
public class Rest {

  @GET
  @Produces("application/json")
  public static Response FindPaths(@QueryParam("id1") Long id1, @QueryParam("id2") Long id2)
      throws JSONException {
    HttpClient httpclient = HttpClients.createDefault();
    String expr = "Composite(AA.AuId=" + id1 + ")&count=10000&attributes=Id,AA.AuId,AA.AfId";
    JSONObject json = SendRequset(httpclient, expr);
    JSONArray entities1 = json.getJSONArray("entities");

    expr = "Composite(AA.AuId=" + id2 + ")&count=10000&attributes=Id,AA.AuId,AA.AfId";
    json = SendRequset(httpclient, expr);
    JSONArray entities2 = json.getJSONArray("entities");

    List<List<Long>> paths = null;
    if (entities1.length() == 0 && entities2.length() == 0) {
      paths = IdId.Calculate(httpclient, id1, id2);
    } else if (entities1.length() == 0 && entities2.length() > 0) {
      paths = IdAuId.Calculate(httpclient, id1, id2, entities2);
    } else if (entities1.length() > 0 && entities2.length() == 0) {
      paths = AuIdId.Calculate(httpclient, id1, id2, entities1);
    } else {
      paths = AuIdAuId.Calculate(httpclient, id1, id2, entities1, entities2);
    }

    JSONArray response = new JSONArray(paths);
    String result = response.toString();
    return Response.status(200).entity(result).build();
  }

  public static JSONObject SendRequset(HttpClient httpclient, String expr) {
    String response = MAGAPI.Get(httpclient, expr);
    // System.out.println(response);
    // error checking
    // while (response == null) response = MAGAPI.Get(httpclient, expr);
    // while(regex解析response的值为error) response = MAGAPI.Get(httpclient, expr);
    return new JSONObject(response);
  }
}

