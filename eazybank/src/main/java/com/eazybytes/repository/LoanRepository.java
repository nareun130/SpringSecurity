package com.eazybytes.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

import com.eazybytes.model.Loans;

@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {
	
	// @PreAuthorize("hasRole('USER')")//* 내부적으로 접두사 추가
	List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);

}
