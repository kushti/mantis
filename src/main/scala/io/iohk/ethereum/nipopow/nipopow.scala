package io.iohk.ethereum.nipopow

import akka.util.ByteString
import io.iohk.ethereum.blockchain.sync.SyncController
import io.iohk.ethereum.crypto.{kec256, kec512, keyPairFromPrvKey}
import io.iohk.ethereum.domain._
import io.iohk.ethereum.network.{PeerManagerActor, ServerActor}
import io.iohk.ethereum.nipopow.Nipopow.Height
import io.iohk.ethereum.nodebuilder.Node
import io.iohk.ethereum.transactions.PendingTransactionsManager.AddTransactions
import io.iohk.ethereum.utils.Logger
import org.spongycastle.crypto.AsymmetricCipherKeyPair
import org.spongycastle.crypto.params.ECPublicKeyParameters
import org.spongycastle.util.encoders.Hex

import scala.concurrent.Await
import scala.util.{Failure, Success, Try}


/**
  * Class to store information about superchain
  *
  * @param level - level of the superchain
  * @param blocks - blocks of the superchain
  */
case class Level(level: Int, blocks: Seq[(Height, BlockHeader)]) {
  lazy val numBlocks: Int = blocks.size

  def withBlock(height: Height, block: BlockHeader): Level =
    this.copy(level = level, (height -> block) +: blocks)

  def lastId: ByteString = blocks.head._2.hash
}


object Nipopow {
  
  type InterlinkVector = Map[Int, Level]
  type Height = BigInt

  def constructInnerchain(startHeight: Height, boundary: Height, level: Level): Level = {
    val newblocks = level.blocks.filter(t => t._1 > boundary && t._1 < startHeight)
    Level(level.level, newblocks)
  }

  def numberOfBlocks(iv: InterlinkVector): Int = iv.values.map(_.numBlocks).sum

  def numberOfUniqueBlocks(iv: InterlinkVector): Int = iv.values.toSeq.flatMap(_.blocks).map(_._1).toSet.size

  def prove(m: Int, k: Int, height: Height, vector: InterlinkVector): InterlinkVector = {
    val v = vector.filter(_._2.numBlocks >= m)
    val maxLevel = v.maxBy(_._1)._1
    maxLevel.to(1, -1).foldLeft((Map(): InterlinkVector, 1: Height)) { case ((iv, boundary), levelNum) =>
      val level = v(levelNum)
      val l = constructInnerchain(height - k, boundary, level)
      val newBoundary = level.blocks.drop(m - 1).head._1
      iv.updated(levelNum, l) -> newBoundary
    }._1
  }

  def calculatePoWValue(blockHeader: BlockHeader): ByteString = {
    val nonceReverted = blockHeader.nonce.reverse
    val hashBlockWithoutNonce = kec256(BlockHeader.getEncodedWithoutNonce(blockHeader))
    val seedHash = kec512(hashBlockWithoutNonce ++ nonceReverted)

    ByteString(kec256(seedHash ++ blockHeader.mixHash))
  }

  private def levels(blockHeader: BlockHeader): Seq[Int] = (1 to 256).takeWhile {level => isLevel(blockHeader, level)}

  private def isLevel(blockHeader: BlockHeader, level: Int): Boolean = {
    val powBoundary = BigInt(2).pow(256) / blockHeader.difficulty / BigInt(2).pow(level)
    val powValue = BigInt(1, calculatePoWValue(blockHeader).toArray)
    powValue <= powBoundary
  }

  def updateInterlinkVector(vector: InterlinkVector, blockHeader: BlockHeader, height: BigInt): InterlinkVector =
    levels(blockHeader).foldLeft(vector) { case (v, levelNum) =>
      val level = v.get(levelNum)
        .map(_.withBlock(height, blockHeader))
        .getOrElse(Level(levelNum, Seq(height -> blockHeader)))
      v.updated(levelNum, level)
    }


  def buildVector(blockchain: Blockchain, bestBlock: BigInt): ByteString = {

    var vector: InterlinkVector = Map()

    (1 to bestBlock.toInt).foreach { i =>
      val h = blockchain.getBlockHeaderByNumber(i).get
      vector = updateInterlinkVector(vector, h, i)
      if (vector.nonEmpty) {
        val maxLevel = vector.maxBy(_._1)
        println("block#: " + i + " maxLevel: " + maxLevel._1)
      }
    }

    val maxLevel = vector.maxBy(_._1)._1
    val payload =
      (1 to maxLevel)
        .map(vector.apply)
        .map(_.lastId)
        .reduce(_ ++ _)

    println("bestBlock: " + bestBlock + " payload length: " + payload.size)
    println(numberOfBlocks(vector))
    val p = prove(m = 10, k = 6, bestBlock, vector)
    println("proving: " + numberOfUniqueBlocks(p))
    payload
  }
}


object NipopowTester extends App {

  import Nipopow._

  new Node with Logger {

    def tryAndLogFailure(f: () => Any): Unit = Try(f()) match {
      case Failure(e) => log.warn("Error while shutting down...", e)
      case Success(_) =>
    }

    override def shutdown(): Unit = {
      tryAndLogFailure(() => Await.ready(actorSystem.terminate, shutdownTimeoutDuration))
      tryAndLogFailure(() => storagesInstance.dataSources.closeAll())
    }

    genesisDataLoader.loadGenesisData()


    peerManager ! PeerManagerActor.StartConnecting
    server ! ServerActor.StartServer(networkConfig.Server.listenAddress)
    syncController ! SyncController.StartSync

    if (jsonRpcHttpServerConfig.enabled) jsonRpcHttpServer.run()

    Thread.sleep(5000)


    val bestBlock = storagesInstance.storages.appStateStorage.getBestBlockNumber()
    println("bb: " + bestBlock)


    val pubKey = Hex.decode("095c83388fde9af08f2ca82201afdb1a37d1ca548f95cb5e3c83f56401fb3b645064c2a7022f6f8d7caae9e6" +
      "a28d56cb542d54e35a9eccc6b38351a7623727a6")
    val privKey = Hex.decode("7e69628779e7f2b540cec2db3083d4013cc186bef13a7a59836819aae7657341")

    val newAccountKeyPair: AsymmetricCipherKeyPair = keyPairFromPrvKey(privKey)
    val newAccountAddress = Address(kec256(newAccountKeyPair.getPublic.asInstanceOf[ECPublicKeyParameters].getQ.getEncoded(false).tail))

    println("addr: " + newAccountAddress)

    val accOpt = blockchain.getAccount(newAccountAddress, bestBlock)

    val payload = buildVector(blockchain, bestBlock)

    val tx = new Transaction(nonce = 9, BigInt("34000000000"), 150000, None, 1, payload)
    val stx = SignedTransaction.sign(tx, newAccountKeyPair, None)

    println("stx: " + stx)
    pendingTransactionsManager ! AddTransactions(stx)

  }
}
