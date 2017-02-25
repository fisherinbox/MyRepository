package com.kong.bop;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;

public class AuIdAuId {
  private static int reqNum = 0;

  public static void main(String[] args) {
    HttpClient httpclient = HttpClients.createDefault();
    //
    reqNum = 0;
    // long start = System.currentTimeMillis();
    // List<List<Long>> result = Calculate(httpclient, 2175015405L, 2121939561L);
    // long end = System.currentTimeMillis();
    // System.out.println(result.size() + " paths in " + (end - start) / 1000 + " s:");
    // System.out.println(reqNum + " requests to MAG API");
    // System.out.println(result.toString());
  }

  // public static List<List<Long>> Calculate(HttpClient httpclient, Long AuId1, Long AuId2) {
  public static List<List<Long>> Calculate(HttpClient httpclient, Long AuId1, Long AuId2,
      JSONArray entities1, JSONArray entities2) {
    List<List<Long>> result = new ArrayList<List<Long>>();
    // -- comment when using restful service
    // String expr = "Composite(AA.AuId=" + AuId1 + ")&count=10000&attributes=Id,AA.AuId,AA.AfId";
    // JSONObject json = SendRequset(httpclient, expr);
    // JSONArray entities = json.optJSONArray("entities");
    // if (entities == null || entities.length() == 0) return result;
    // --------------------------------------
    // -- comment when testing locally
    String expr = null;
    JSONObject json = null;
    JSONArray entities = entities1;
    // --------------------------------
    Set<Long> Id1s = new HashSet<Long>();
    for (int i = 0; i < entities.length(); ++i) {
      Id1s.add(entities.getJSONObject(i).getLong("Id"));
    }
    Set<Long> AfId1 = Util.GetAfIds(entities, AuId1);
    // -- comment when using restful service
    // expr = "Composite(AA.AuId=" + AuId2 + ")&count=10000&attributes=Id,AA.AuId,AA.AfId";
    // json = SendRequset(httpclient, expr);
    // entities = json.optJSONArray("entities");
    // if (entities == null || entities.length() == 0) return result;
    // --------------------------------
    // -- comment when testing locally
    entities = entities2;
    // --------------------------------
    Set<Long> Id2s = new HashSet<Long>();
    for (int i = 0; i < entities.length(); ++i) {
      Id2s.add(entities.getJSONObject(i).getLong("Id"));
    }
    Set<Long> AfId2 = Util.GetAfIds(entities, AuId2);

    // 2-hop
    // [AuId1-id-AuId2]
    List<Long> common = Util.Intersection(Id1s, Id2s);
    for (Long id : common) {
      List<Long> element = new ArrayList<>();
      element.add(AuId1);
      element.add(id);
      element.add(AuId2);
      result.add(element);
    }
    // [AuId1-AfId-AuId2]
    common = Util.Intersection(AfId1, AfId2);
    for (Long afid : common) {
      List<Long> element = new ArrayList<>();
      element.add(AuId1);
      element.add(afid);
      element.add(AuId2);
      result.add(element);
    }

    // 3-hop
    // [AuId1-id1-id2-AuId2]
    int n = Id1s.size();
    int mod = 64;
    if (n > 0) {
      List<Long> ids = new ArrayList<>(Id1s);
      int begin = 0;
      while (true) {
        expr = Util.CreateOR(ids, begin, Math.min(begin + mod - 1, n - 1))
            + "&count=10000&attributes=Id,RId";
        json = SendRequset(httpclient, expr);
        entities = json.optJSONArray("entities");
        if (entities != null) {
          for (int i = 0; i < entities.length(); i++) {
            JSONObject obj = entities.getJSONObject(i);
            Long id = obj.getLong("Id");
            Set<Long> RId = new HashSet<>();
            Util.ParseJson(obj, RId, null, null);
            List<Long> same = Util.Intersection(RId, Id2s);
            for (Long rid : same) {
              List<Long> element = new ArrayList<>();
              element.add(AuId1);
              element.add(id);
              element.add(rid);
              element.add(AuId2);
              result.add(element);
            }
          }
        }

        begin += mod;
        if (begin > n - 1) break;
      }
    }

    return result;
  }

  public static JSONObject SendRequset(HttpClient httpclient, String expr) {
    ++reqNum;
    String response = MAGAPI.Get(httpclient, expr);
    // System.out.println(response);
    // error checking
    // while (response == null) response = MAGAPI.Get(httpclient, expr);
    // while(regex解析response的值为error) response = MAGAPI.Get(httpclient, expr);
    return new JSONObject(response);
  }
}
