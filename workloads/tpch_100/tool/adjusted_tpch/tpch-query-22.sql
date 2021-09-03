-- [origin]
select
	cntrycode,
	count(*) as numcust,
	sum(c_acctbal) as totacctbal
from
	(
		select
			substring(c_phone from 1 for 2) as cntrycode,
			c_acctbal
		from
			customer
		where
			substring(c_phone from 1 for 2) in
				('33', '13', '23', '27', '20', '16', '18')
			and c_acctbal > (
				select
					avg(c_acctbal)
				from
					customer
				where
					c_acctbal > 0.00
					and substring(c_phone from 1 for 2) in
						('33', '13', '23', '27', '20', '16', '18')
			)
			and not exists (
				select
					*
				from
					orders
				where
					o_custkey = c_custkey
			)
	) as custsale
group by
	cntrycode
order by
	cntrycode 
 
 -- [default] change join type + decorrelate manually



select
    cntrycode,
    count(1) as numcust,
    sum(c_acctbal) as totacctbal
from (
    select
        substring(c_phone, 1, 2) as cntrycode,
        c_acctbal
    from 
        customer inner join 

        (
    select c_custkey as noordercus
    from
        customer left join orders on c_custkey = o_custkey
    where o_orderkey is null
    group by c_custkey
		)

         on c_custkey = noordercus, 

        (
    select
        avg(c_acctbal) as avg_acctbal
    from
        customer
    where
        c_acctbal > 0.00 and substring(c_phone, 1, 2) in ('33', '13', '23', '27', '20', '16', '18')
)

    where 
        substring(c_phone, 1, 2) in ('33', '13', '23', '27', '20', '16', '18')
        and c_acctbal > avg_acctbal
) t
group by
    cntrycode
order by
    cntrycode
