package com.nareun.easy_bank.controller;

import com.nareun.easy_bank.model.Contact;
import com.nareun.easy_bank.repository.ContactRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@RestController
public class ContactController {

    @Autowired
    private ContactRepository contactRepository;

    @PostMapping("/contact")
//    @PreFilter("filterObject.contactName!='Test'")//* filtering 조건을 걸 때는 매개변수와 리턴이 모두 List여야 한다!!
    @PostFilter("filterObject.contactName!='Test'")
    public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
        //~> contactName이 Test이므로 filtering 되어서 size가 0이 됨.
        Contact contact = contacts.get(0);
        contact.setContactId(getServiceReqNumber());
        contact.setCreateDt(new Date(System.currentTimeMillis()));
        contactRepository.save(contact);

        List<Contact> returnContacts = new ArrayList<>();
        returnContacts.add(contact);
        return returnContacts;
    }

    public String getServiceReqNumber() {
        Random random = new Random();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
