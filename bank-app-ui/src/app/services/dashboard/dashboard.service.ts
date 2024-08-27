import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { AppConstants } from "../../constants/app.constants";
import { environment } from "../../../environments/environment";
import { User } from "../../model/user.model";
import { Contact } from "../../model/contact.model";

@Injectable({
  providedIn: "root",
})
export class DashboardService {
  constructor(private http: HttpClient) {}

  //*withCredentials: true -> 갖고 있는 쿠키와 SessionId or 토큰들을 백엔드로 부터 찾아달라는 요청
  //~> 인증이 필요한 api는 이 옵션이 필요
  getAccountDetails(id: number) {
    return this.http.get(
      environment.rooturl + AppConstants.ACCOUNT_API_URL + "?id=" + id,
      { observe: "response", withCredentials: true }
    );
  }

  getAccountTransactions(id: number) {
    return this.http.get(
      environment.rooturl + AppConstants.BALANCE_API_URL + "?id=" + id,
      { observe: "response", withCredentials: true }
    );
  }

  getLoansDetails(id: number) {
    return this.http.get(
      environment.rooturl + AppConstants.LOANS_API_URL + "?id=" + id,
      { observe: "response", withCredentials: true }
    );
  }

  getCardsDetails(id: number) {
    return this.http.get(
      environment.rooturl + AppConstants.CARDS_API_URL + "?id=" + id,
      { observe: "response", withCredentials: true }
    );
  }

  //* observe: 'response' : 백엔드에게 요청을 전부 달라는 뜻, 헤더와 바디만이 아닌
  getNoticeDetails() {
    return this.http.get(environment.rooturl + AppConstants.NOTICES_API_URL, {
      observe: "response",
    });
  }

  saveMessage(contact: Contact) {
    var contacts = [];
    contacts.push(contact);
    return this.http.post(
      environment.rooturl + AppConstants.CONTACT_API_URL,
      // contact,
      contacts,
      { observe: "response" }
    );
  }
}
